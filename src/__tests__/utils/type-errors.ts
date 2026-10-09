/**
 * Type-check a module that exists only in memory, for tests that pin what
 * consumer code compiles against.
 */
import { fileURLToPath } from 'node:url';
import ts from 'typescript';

/**
 * Type-checks `source` as an in-memory module at `at`, with strict options,
 * and returns the formatted diagnostics ('' when it compiles). The module
 * resolves its imports as a file at `at` would. The compiler hands the host
 * `/`-separated names and folds case on case-insensitive file systems, so the
 * module is matched by canonical name, never by comparing raw OS paths.
 */
export function typeErrors(source: string, at: URL): string {
  const options: ts.CompilerOptions = {
    target: ts.ScriptTarget.ES2022,
    module: ts.ModuleKind.NodeNext,
    moduleResolution: ts.ModuleResolutionKind.NodeNext,
    lib: ['lib.es2022.d.ts'],
    types: [],
    strict: true,
    noEmit: true,
    skipLibCheck: true,
  };
  const host = ts.createCompilerHost(options);
  const canonical = (name: string): string => host.getCanonicalFileName(name.replace(/\\/g, '/'));
  const fileName = fileURLToPath(at).replace(/\\/g, '/');
  const isModule = (name: string): boolean => canonical(name) === canonical(fileName);
  const { fileExists, readFile, getSourceFile } = host;
  host.fileExists = (name) => isModule(name) || fileExists.call(host, name);
  host.readFile = (name) => (isModule(name) ? source : readFile.call(host, name));
  host.getSourceFile = (name, languageVersion, ...rest) => (isModule(name)
    ? ts.createSourceFile(name, source, languageVersion, true)
    : getSourceFile.call(host, name, languageVersion, ...rest));
  const program = ts.createProgram([fileName], options, host);
  const module = program.getSourceFile(fileName);
  const formatted = ts.formatDiagnostics(
    module === undefined ? ts.getPreEmitDiagnostics(program) : ts.getPreEmitDiagnostics(program, module),
    {
      getCanonicalFileName: (name) => name,
      getCurrentDirectory: () => ts.sys.getCurrentDirectory(),
      getNewLine: () => '\n',
    },
  );
  return module === undefined ? `in-memory module ${fileName} was not loaded\n${formatted}` : formatted;
}
