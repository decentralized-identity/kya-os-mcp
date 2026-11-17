/**
 * Which requests of a read are the operator's own. A URL is named byte for byte, as the keeper binds
 * a list's URL to its issuer: the first request by the URL as the read was given it, so another
 * spelling of a bound URL, with its host in upper case or a `/./` in its path, is not the operator's
 * though the URL parser writes it the same; a redirect by the URL the follower resolved. Only a
 * `true` names a URL, and a namer that throws, or is not a function, names none.
 */

import { describe, expect, it } from 'vitest';
import { guardedNamer, operatorNamedRequests } from '../operator-named.js';

const BOUND = 'https://lists.corp.example/acme';
const bound = (url: string) => url === BOUND;

describe('the first request of a read', () => {
  it('is the operator’s when the URL the read was given is the one it named, as written', () => {
    expect(operatorNamedRequests(BOUND, bound)(BOUND)).toBe(true);
  });

  it.each([
    ['its host in upper case', 'https://LISTS.corp.example/acme'],
    ['a /./ in its path', 'https://lists.corp.example/./acme'],
    ['a default port written out', 'https://lists.corp.example:443/acme'],
  ])('is not the operator’s when the read was given the named URL with %s, which the URL parser writes as it', (_case, spelled) => {
    expect(new URL(spelled).href).toBe(BOUND);
    expect(operatorNamedRequests(spelled, bound)(BOUND)).toBe(false);
  });
});

describe('a redirect of a read', () => {
  it('is the operator’s when the URL it asks for is one the operator named, and not otherwise', () => {
    const requests = operatorNamedRequests('https://lists.example/moved', bound);
    expect(requests(BOUND)).toBe(true);
    expect(requests('https://lists.corp.example/other')).toBe(false);
  });

  it('back to the first URL is decided as the first request is', () => {
    expect(operatorNamedRequests('https://LISTS.corp.example/acme', bound)(BOUND)).toBe(false);
  });
});

describe('a namer', () => {
  it.each([
    ['answers something other than true', () => 'yes'],
    ['throws', () => { throw new Error('no'); }],
    ['is not a function', 'not a function'],
  ])('names nothing when it %s', (_case, named) => {
    expect(guardedNamer(named)(BOUND)).toBe(false);
    expect(operatorNamedRequests(BOUND, named as (url: string) => boolean)(BOUND)).toBe(false);
  });
});
