/**
 * Every refusal the library builds carries a refusal code from the catalog and whether it is
 * transient. This walks the library's own source, with the TypeScript checker, and finds each
 * object literal shaped as a refusal: one that states `valid: false`, `ok: false` or
 * `revoked: true`. Each must have, as members its type requires, `transient` and either a
 * `refusalCode` or a `code`, typed as codes of the catalog and nothing else: a gate code such as
 * `delegation_missing` alone does not count. A literal that builds its members from a coding
 * helper, `...coded(code)` or `...refusal`, has them in its type, and passes.
 *
 * The few modules whose refusal-shaped literals are not refusals of the library's verifiers, or
 * are answers a verifier codes when it reads them, are listed below, each with why and with how
 * many such literals it holds, so a new one in them fails here too.
 */

import { dirname, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import ts from 'typescript';
import { describe, expect, it } from 'vitest';
import { isRefusalCode } from '../refusal-codes.js';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../..');

/** The members whose literal value makes an object literal a refusal. */
const REFUSAL_MARKS: Record<string, string> = { valid: 'false', ok: 'false', revoked: 'true' };

/** Modules whose refusal-shaped literals carry no code, why, and how many there are. */
const NOT_CODED: Record<string, { literals: number; why: string }> = {
  'src/delegation/embedded-signature.ts': {
    literals: 4,
    why: "the signature verifier the middleware supplies answers its port, whose shape the conformance suite pins; the credential verifier codes a refusal it gives by the code it names, did_invalid for a key it cannot read, else invalid_proof",
  },
  'src/auth/delegation-verdict.ts': {
    literals: 1,
    why: 'a verdict that is valid but names no delegation is refused by the handshake, not by the verifier, so it carries none of the codes the handshake hands the operator',
  },
  'src/utils/statuslist-acceptance.ts': {
    literals: 1,
    why: "a status list rule's verdict; every reader of it throws it as a RefusalError with the code of the rule",
  },
  'src/delegation/did-document-walk.ts': {
    literals: 2,
    why: 'the measure of a DID document; the resolver reports a document it refuses with the cause invalid_document, coded did_invalid',
  },
  'src/delegation/cascading-revocation.ts': {
    literals: 2,
    why: 'the revocation manager answers the revocation checker port, which the chain walk reads and codes, and checks records it stores',
  },
  'src/delegation/delegation-graph.ts': {
    literals: 3,
    why: 'the delegation graph checks the records it stores, not a credential presented to a verifier',
  },
  'src/proof/verifier.ts': { literals: 10, why: 'a request proof refusal carries an errorCode from the proof error codes' },
  'src/card/proof/verify.ts': { literals: 1, why: "a card request proof's reasons are its codes" },
  'src/card/verify.ts': { literals: 2, why: "a card request proof's reasons are its codes" },
  'src/card/middleware.ts': { literals: 2, why: "requireProof answers a request proof, whose reasons are its codes, in an error with a code" },
  'src/delegation/did-linkage.ts': { literals: 5, why: 'the linkage of two DID documents, reported with the checks it ran' },
  'src/integrations/cheqd/dlr.ts': { literals: 7, why: 'the shape of a DID-linked resource artifact, not a verdict on a credential' },
  'src/authz/oidc/oidc-adapter.ts': { literals: 7, why: 'an OAuth authorization code exchange, not a verdict on a credential' },
  'src/extension/gate.ts': { literals: 2, why: 'an extension declaration, refused with an error of its own' },
  'src/audit/checkpoint-coordinator.ts': { literals: 2, why: 'a checkpoint provider failure, not a verdict on a credential' },
};

interface RefusalLiteral {
  file: string;
  line: number;
  text: string;
  coded: boolean;
}

/** Each refusal-shaped object literal in the library's source, and whether its type carries a code. */
function refusalLiterals(): RefusalLiteral[] {
  const configFile = ts.readConfigFile(resolve(ROOT, 'tsconfig.json'), ts.sys.readFile);
  const parsed = ts.parseJsonConfigFileContent(configFile.config, ts.sys, ROOT);
  const program = ts.createProgram(parsed.fileNames, { ...parsed.options, noEmit: true });
  const checker = program.getTypeChecker();

  const required = (type: ts.Type, name: string): ts.Symbol | undefined => {
    const member = type.getProperty(name);
    return member !== undefined && (member.flags & ts.SymbolFlags.Optional) === 0 ? member : undefined;
  };
  const catalogCode = (member: ts.Symbol | undefined, at: ts.Node): boolean => {
    if (member === undefined) return false;
    const type = checker.getTypeOfSymbolAtLocation(member, at);
    return (type.isUnion() ? type.types : [type]).every((part) => part.isStringLiteral() && isRefusalCode(part.value));
  };
  const isCoded = (literal: ts.ObjectLiteralExpression): boolean => {
    const type = checker.getTypeAtLocation(literal);
    if (required(type, 'transient') === undefined) return false;
    const refusalCode = required(type, 'refusalCode');
    return refusalCode !== undefined ? catalogCode(refusalCode, literal) : catalogCode(required(type, 'code'), literal);
  };

  const found: RefusalLiteral[] = [];
  for (const source of program.getSourceFiles()) {
    const file = relative(ROOT, source.fileName);
    if (source.isDeclarationFile || !file.startsWith('src/')) continue;
    const visit = (node: ts.Node): void => {
      if (ts.isObjectLiteralExpression(node)) {
        const marked = node.properties.some(
          (member) =>
            ts.isPropertyAssignment(member) &&
            ts.isIdentifier(member.name) &&
            REFUSAL_MARKS[member.name.text] === member.initializer.getText(source),
        );
        if (marked) {
          const { line } = source.getLineAndCharacterOfPosition(node.getStart(source));
          found.push({ file, line: line + 1, text: node.getText(source).replace(/\s+/g, ' ').slice(0, 120), coded: isCoded(node) });
        }
      }
      ts.forEachChild(node, visit);
    };
    visit(source);
  }
  return found;
}

describe('the refusals the library builds', () => {
  const literals = refusalLiterals();
  const uncoded = literals.filter((literal) => !literal.coded);

  it('each carry a code of the catalog and transient, outside the modules listed with why', () => {
    const unlisted = uncoded.filter((literal) => NOT_CODED[literal.file] === undefined);
    expect(unlisted.map(({ file, line, text }) => `${file}:${line} ${text}`)).toEqual([]);
  });

  it('hold, in each listed module, exactly as many literals without a code as it lists', () => {
    const counted: Record<string, number> = {};
    for (const { file } of uncoded) counted[file] = (counted[file] ?? 0) + 1;
    const listed = Object.fromEntries(Object.entries(NOT_CODED).map(([file, { literals: count }]) => [file, count]));
    expect(counted).toEqual(listed);
  });

  it('are found where the verifiers build them, so the walk reads the source it should', () => {
    const codedIn = new Set(literals.filter((literal) => literal.coded).map((literal) => literal.file));
    for (const file of [
      'src/delegation/vc-verification-checks.ts',
      'src/delegation/vc-jwt-verify.ts',
      'src/delegation/chain-enforcement.ts',
      'src/card/delegation.ts',
      'src/card/request-delegation.ts',
      'src/middleware/with-kya-os.delegation-check.ts',
      'src/middleware/with-kya-os.delegation-verify.ts',
      'src/card/revocation.ts',
      'src/card/revocation-chain.ts',
      'src/card/verify-revocation.ts',
      'src/card/carried-chain.ts',
      'src/utils/verdict.ts',
    ]) {
      expect([...codedIn], file).toContain(file);
    }
  });
}, 60_000);
