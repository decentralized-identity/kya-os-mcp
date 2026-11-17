/**
 * The words of the remedy a keeper refusal ends with (`./statuslist-remedy`): the
 * `statusListIssuers` configuration that would accept a list, or where to name the list's issuer.
 * An operator copies that configuration out of a reason, so a reason carries a remedy whole or not
 * at all. The words are written and recognised here, in one place, so that `sanitizeForMessage`,
 * wherever it cuts a reason for length, cuts before a remedy the cut would split, whatever words a
 * host's resolver or checker put before it ({@link withoutPartialRemedy}).
 */

/** How every remedy opens. */
const OPENING = '; if ';
/** How a remedy that names the list's issuer opens: with the DID, quoted. */
const DID_OPENING = `${OPENING}"did:`;
/** How a remedy that does not name the list's issuer opens. */
const ISSUER_OPENING = `${OPENING}the list's issuer `;

/** The condition of a remedy when no binding names the URL's keeper. */
const SIGNS_ISSUER_LISTS = "signs this issuer's lists";
/** The condition of a remedy when a binding names the URL's keeper. */
const SIGNS_LIST_AT_URL = 'signs the list at this URL';
/** What a remedy that prints the configuration asks, when no binding names the signer and when one names another. */
const NAME_IT = 'name it';
const MOVE_BINDING = "move the URL's binding to it";

/** A DID as a remedy prints one: every character JSON writes as itself. */
const DID = 'did:[a-z0-9]+:[A-Za-z0-9._:%-]+';
/** A URL as a remedy prints one: visible ASCII, with nothing JSON would escape. */
const URL_TEXT = '[\\x21\\x23-\\x5b\\x5d-\\x7e]+';

/** A DID a remedy can print whole and exactly. */
export const PRINTABLE_DID = new RegExp(`^${DID}$`);
/** A URL a remedy can print whole and exactly. */
export const PRINTABLE_URL = new RegExp(`^${URL_TEXT}$`);

/** The remedy that names no value, for a keeper no binding names. */
export const UNBOUND_GENERAL_REMEDY =
  `${ISSUER_OPENING}${SIGNS_ISSUER_LISTS}, ${NAME_IT} in statusListIssuers with this list's https origin or URL`;
/** The remedy that names no value, for a keeper a binding names. */
export const BOUND_GENERAL_REMEDY = `${ISSUER_OPENING}${SIGNS_LIST_AT_URL}, bind the URL to it in statusListIssuers`;

/** What an exact remedy asks of the operator: where no binding names the keeper, where one names it, and where one names the URL itself. */
export type ExactRemedyKind = 'unbound' | 'bound' | 'moved';

/**
 * The remedy that prints the configuration binding `binding` to `signer`, a DID and a URL that
 * {@link PRINTABLE_DID} and {@link PRINTABLE_URL} take, as a condition the operator judges.
 */
export function exactRemedy(signer: string, binding: string, kind: ExactRemedyKind): string {
  const condition = kind === 'unbound' ? SIGNS_ISSUER_LISTS : SIGNS_LIST_AT_URL;
  const action = kind === 'moved' ? MOVE_BINDING : NAME_IT;
  const did = JSON.stringify(signer);
  return `${OPENING}${did} ${condition}, ${action} in statusListIssuers: { ${did}: [${JSON.stringify(binding)}] }`;
}

/** `text` with every character a pattern reads specially escaped. */
const literal = (text: string): string => text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/** A whole remedy, at the position it is asked about: an exact one, or either general one. */
const WHOLE_REMEDY = new RegExp(
  [
    `${literal(OPENING)}"${DID}" (?:${literal(SIGNS_ISSUER_LISTS)}|${literal(SIGNS_LIST_AT_URL)}), ` +
      `(?:${literal(NAME_IT)}|${literal(MOVE_BINDING)}) in statusListIssuers: \\{ "${DID}": \\["${URL_TEXT}"\\] \\}`,
    literal(UNBOUND_GENERAL_REMEDY),
    literal(BOUND_GENERAL_REMEDY),
  ].join('|'),
  'y',
);

/**
 * Where the last remedy in `text` opens, whole or cut within its opening, or `-1` when none does. A
 * text that ends inside an opening, from `; if ` on, counts as opening one there.
 */
function lastOpening(text: string): number {
  let start = -1;
  for (const opening of [DID_OPENING, ISSUER_OPENING]) {
    start = Math.max(start, text.lastIndexOf(opening));
    for (let length = opening.length - 1; length >= OPENING.length; length--) {
      if (text.endsWith(opening.slice(0, length))) {
        start = Math.max(start, text.length - length);
        break;
      }
    }
  }
  return start;
}

/**
 * `text`, a reason cut for length, without the remedy the cut fell inside: the last remedy that
 * opens in it, if any, unless it ends within it. Nothing else is taken away.
 */
export function withoutPartialRemedy(text: string): string {
  const start = lastOpening(text);
  if (start < 0) return text;
  WHOLE_REMEDY.lastIndex = start;
  return WHOLE_REMEDY.test(text) ? text : text.slice(0, start);
}
