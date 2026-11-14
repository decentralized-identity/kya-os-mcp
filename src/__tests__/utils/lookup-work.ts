/**
 * A deterministic work model for the real lookup source, not a JavaScript benchmark. Count loop
 * iterations/calls and upper bounds on UTF-16 units examined or copied. In particular, primitive
 * equality, `+` and template literals are instrumented: String.prototype spies cannot see them.
 * Native operations without a cost rule are rejected rather than silently counted as constant.
 * Supplied imports are trusted helpers, outside this model; callers must provide them explicitly.
 */
import { runInNewContext } from 'node:vm';
import ts from 'typescript';

export function compileMeteredLookup(source: string, imports: Record<string, unknown>): {
  exports: Record<string, unknown>;
  reset(budget: number): void;
  work(): number;
  step(): void;
} {
  let consumed = 0;
  let limit = Infinity;
  function charge(units = 1): void {
    consumed += units;
    if (consumed > limit) throw new Error(`Lookup work budget exceeded: ${consumed} > ${limit}`);
  }
  function unsupported(operation: string): never {
    throw new Error(`Unmetered lookup operation: ${operation}; add an explicit cost rule`);
  }
  const meter = {
    step: charge,
    equal(left: unknown, right: unknown): boolean {
      charge(1 + (typeof left === 'string' && typeof right === 'string' && left.length === right.length ? left.length : 0));
      return left === right;
    },
    add(left: unknown, right: unknown): unknown {
      // Parsed input gives primitives here. Object coercion could call arbitrary unmetered code.
      for (const value of [left, right]) {
        if ((typeof value === 'object' && value !== null) || typeof value === 'function') unsupported('object coercion in +');
      }
      // Assertions only satisfy TypeScript: the emitted + retains JavaScript's actual semantics.
      const result: unknown = (left as number) + (right as number);
      charge(1 + (typeof result === 'string' ? result.length : 0));
      return result;
    },
    template(value: string): string {
      charge(1 + value.length);
      return value;
    },
    interpolate(value: unknown): unknown {
      if ((typeof value === 'object' && value !== null) || typeof value === 'function') unsupported('object coercion in template');
      return value;
    },
    read(receiver: unknown, key: unknown): unknown {
      if (typeof key !== 'string' && typeof key !== 'number' && typeof key !== 'symbol') unsupported('computed property coercion');
      charge(1 + (typeof key === 'string' ? key.length : 0));
      return (receiver as Record<PropertyKey, unknown>)[key];
    },
    has(key: unknown, receiver: unknown): boolean {
      if (typeof key !== 'string' && typeof key !== 'number' && typeof key !== 'symbol') unsupported('property-name coercion');
      charge(1 + (typeof key === 'string' ? key.length : 0));
      return key in (receiver as object);
    },
    call(fn: (...args: unknown[]) => unknown, ...args: unknown[]): unknown {
      charge();
      return Reflect.apply(fn, undefined, args);
    },
    string(receiver: unknown, method: string, ...args: unknown[]): unknown {
      if (typeof receiver !== 'string') unsupported(`${method} on a non-string`);
      const size = receiver.length;
      const integer = (value: unknown, fallback: number): number => {
        if (value === undefined) return fallback;
        if (typeof value !== 'number') unsupported(`${method} with a non-numeric position`);
        return Number.isNaN(value) ? 0 : Math.trunc(value);
      };
      if (method === 'slice') {
        if (args.length > 2) unsupported('slice with extra arguments');
        const index = (value: unknown, fallback: number): number => {
          const n = integer(value, fallback);
          return n < 0 ? Math.max(size + n, 0) : Math.min(n, size);
        };
        charge(1 + Math.max(0, index(args[1], size) - index(args[0], 0)));
        return Reflect.apply(String.prototype.slice, receiver, args);
      }
      if (method !== 'startsWith' && method !== 'includes') unsupported(method);
      const needle = args[0];
      if (typeof needle !== 'string' || args.length > 2) unsupported(`${method} arguments`);
      const remaining = size - Math.min(size, Math.max(0, integer(args[1], 0)));
      // A too-long needle fails by length alone. includes uses a conservative naive-search bound;
      // for the lookup's single-character '#' it is exactly the available input length.
      const examined = needle.length > remaining ? 0 : method === 'startsWith'
        ? needle.length : (remaining - needle.length + 1) * needle.length;
      charge(1 + examined);
      return Reflect.apply(method === 'startsWith' ? String.prototype.startsWith : String.prototype.includes, receiver, args);
    },
  };

  const transformer: ts.TransformerFactory<ts.SourceFile> = (context) => (file) => {
    const factory = context.factory;
    const callable = new Set<string>();
    const collect = (node: ts.Node): void => {
      if (ts.isFunctionDeclaration(node) && node.name) callable.add(node.name.text);
      if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer &&
          (ts.isArrowFunction(node.initializer) || ts.isFunctionExpression(node.initializer))) callable.add(node.name.text);
      if (ts.isImportDeclaration(node) && !node.importClause?.isTypeOnly) {
        const bindings = node.importClause?.namedBindings;
        if (bindings && ts.isNamedImports(bindings)) {
          for (const binding of bindings.elements) if (!binding.isTypeOnly) callable.add(binding.name.text);
        }
      }
      ts.forEachChild(node, collect);
    };
    collect(file);
    const invoke = (name: string, args: readonly ts.Expression[]): ts.CallExpression =>
      factory.createCallExpression(factory.createPropertyAccessExpression(factory.createIdentifier('__lookupWork'), name), undefined, args);
    const loopBody = (body: ts.Statement): ts.Block => factory.createBlock([
      factory.createExpressionStatement(invoke('step', [])),
      ...(ts.isBlock(body) ? body.statements : [body]),
    ], true);
    const visit: ts.Visitor = (original) => {
      if (ts.isNewExpression(original) || ts.isTaggedTemplateExpression(original) || ts.isSpreadElement(original) ||
          ts.isSpreadAssignment(original) || ts.isRegularExpressionLiteral(original) || ts.isComputedPropertyName(original) ||
          ts.isDeleteExpression(original)) unsupported(original.getText(file));
      // Computed writes need reference-preserving instrumentation and a hash/copy cost rule.
      if ((ts.isBinaryExpression(original) && ts.isElementAccessExpression(original.left) &&
          original.operatorToken.kind >= ts.SyntaxKind.FirstAssignment && original.operatorToken.kind <= ts.SyntaxKind.LastAssignment) ||
          ((ts.isPrefixUnaryExpression(original) || ts.isPostfixUnaryExpression(original)) && ts.isElementAccessExpression(original.operand))) {
        unsupported(original.getText(file));
      }
      const node = ts.visitEachChild(original, visit, context);
      if (ts.isBinaryExpression(node)) {
        const op = node.operatorToken.kind;
        if (op === ts.SyntaxKind.PlusToken) return invoke('add', [node.left, node.right]);
        if (op === ts.SyntaxKind.InKeyword) return invoke('has', [node.left, node.right]);
        if (op === ts.SyntaxKind.EqualsEqualsEqualsToken || op === ts.SyntaxKind.ExclamationEqualsEqualsToken) {
          const equality = invoke('equal', [node.left, node.right]);
          return op === ts.SyntaxKind.EqualsEqualsEqualsToken ? equality : factory.createPrefixUnaryExpression(ts.SyntaxKind.ExclamationToken, equality);
        }
        if (op === ts.SyntaxKind.PlusEqualsToken || op === ts.SyntaxKind.EqualsEqualsToken || op === ts.SyntaxKind.ExclamationEqualsToken) {
          unsupported(original.getText(file));
        }
      }
      if (ts.isTemplateExpression(node)) return invoke('template', [factory.updateTemplateExpression(node, node.head,
        node.templateSpans.map((span) => factory.updateTemplateSpan(span, invoke('interpolate', [span.expression]), span.literal)))]);
      if (ts.isElementAccessExpression(node)) {
        if (node.questionDotToken) unsupported(original.getText(file));
        return invoke('read', [node.expression, node.argumentExpression]);
      }
      if (ts.isCallExpression(node)) {
        if (node.questionDotToken || node.arguments.some(ts.isSpreadElement)) unsupported(original.getText(file));
        const callee = node.expression;
        if (ts.isIdentifier(callee) && callable.has(callee.text)) return invoke('call', [callee, ...node.arguments]);
        if (ts.isPropertyAccessExpression(callee) && !callee.questionDotToken) {
          if (ts.isIdentifier(callee.expression) && callee.expression.text === 'Array' && callee.name.text === 'isArray') {
            return invoke('call', [callee, ...node.arguments]);
          }
          if (['includes', 'startsWith', 'slice'].includes(callee.name.text)) {
            return invoke('string', [callee.expression, factory.createStringLiteral(callee.name.text), ...node.arguments]);
          }
        }
        unsupported(original.getText(file));
      }
      if (ts.isForOfStatement(node)) {
        if (node.awaitModifier) unsupported('for await');
        return factory.updateForOfStatement(node, undefined, node.initializer, node.expression, loopBody(node.statement));
      }
      if (ts.isForInStatement(node)) return factory.updateForInStatement(node, node.initializer, node.expression, loopBody(node.statement));
      if (ts.isForStatement(node)) return factory.updateForStatement(node, node.initializer, node.condition, node.incrementor, loopBody(node.statement));
      if (ts.isWhileStatement(node)) return factory.updateWhileStatement(node, node.expression, loopBody(node.statement));
      if (ts.isDoStatement(node)) return factory.updateDoStatement(node, loopBody(node.statement), node.expression);
      return node;
    };
    return ts.visitNode(file, visit) as ts.SourceFile;
  };
  const compiled = ts.transpileModule(source, {
    fileName: 'verification-relationship.ts',
    compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS },
    transformers: { before: [transformer] },
    reportDiagnostics: true,
  });
  const errors = compiled.diagnostics?.filter((diagnostic) => diagnostic.category === ts.DiagnosticCategory.Error) ?? [];
  if (errors.length) throw new Error(ts.formatDiagnosticsWithColorAndContext(errors, {
    getCurrentDirectory: () => '', getCanonicalFileName: (name) => name, getNewLine: () => '\n',
  }));
  const exported: Record<string, unknown> = {};
  runInNewContext(compiled.outputText, {
    exports: exported,
    __lookupWork: meter,
    require: (name: string): unknown => {
      if (!Object.prototype.hasOwnProperty.call(imports, name)) unsupported(`import ${name}`);
      return imports[name];
    },
  }, { timeout: 1_000, filename: 'verification-relationship.metered.cjs' });
  return {
    exports: exported,
    reset(budget) {
      if (!Number.isFinite(budget) || budget < 0) throw new Error('Lookup work budget must be finite and nonnegative');
      consumed = 0;
      limit = budget;
    },
    work: () => consumed,
    step: () => charge(),
  };
}
