import { createParamDecorator, ExecutionContext, ForbiddenException } from '@nestjs/common';
import { IncomingMessage } from 'http';
import { IGrantedPrincipalProvider } from '../services';

export interface ClaimOptions {
  /** Expected type of the value — of each element with `array`. Unchecked when unset. */
  type?: 'string' | 'number' | 'boolean';
  /** The value is a list. A single value is taken as a list of one. */
  array?: boolean;
  /** Refuse the request (403) when the claim is missing or doesn't have the expected type. */
  required?: boolean;
}

interface ClaimParam extends ClaimOptions {
  name: string;
}

/** Marks a value that doesn't have the expected type. */
const INVALID = Symbol('invalid');

/**
 * Injects any attribute of the caller — a JWT claim (dotted paths allowed,
 * e.g. `'realm_access.territories'`) or a gateway header — as the configured
 * {@link IGrantedPrincipalProvider} resolves it. Roles decide *which* actions
 * are allowed; claims scope *which* data they may touch.
 *
 * A string value is parsed: `array` reads a JSON array (`["FR","GP"]`) or a
 * comma-separated list (`FR, GP`), `number` and `boolean` convert strictly.
 * A missing value yields `undefined` (`[]` with `array`); so does a value of
 * the wrong type, with a warning. In a list, only the elements of the wrong
 * type are dropped — with a warning too.
 *
 * ```ts
 * list(@Claim('territories', { type: 'string', array: true }) territories: string[])
 * ```
 */
export function Claim(name: string, options: ClaimOptions = {}): ParameterDecorator {
  return ClaimParam({ ...options, name });
}

const ClaimParam = createParamDecorator((param: ClaimParam, ctx: ExecutionContext) => {
  const incomingMessage: IncomingMessage = ctx.switchToHttp().getRequest<IncomingMessage>();
  const grantedPrincipalProvider: IGrantedPrincipalProvider = incomingMessage['grantedPrincipalProvider'];
  if (!grantedPrincipalProvider?.getClaimFromIncomingMessage) {
    throw new Error(`[nestjs-granted] @Claim('${param.name}') needs a principal provider implementing getClaimFromIncomingMessage`);
  }
  const { value, dropped } = convert(grantedPrincipalProvider.getClaimFromIncomingMessage(incomingMessage, param.name), param);
  // Never log the value: it comes from the caller's token or headers.
  if (value === INVALID) {
    console.warn(`[nestjs-granted] claim '${param.name}' is not of the expected type (${param.type ?? 'any'}${param.array ? '[]' : ''}): ignored`);
  } else if (dropped) {
    console.warn(`[nestjs-granted] claim '${param.name}': ${dropped} element(s) not of the expected type (${param.type}) ignored`);
  }
  if (value === undefined || value === INVALID) {
    if (param.required) {
      throw new ForbiddenException();
    }
    return param.array ? [] : undefined;
  }
  return value;
});

/** The converted value, and how many list elements of the wrong type were dropped from it. */
function convert(raw: unknown, { type, array }: ClaimOptions): { value: unknown; dropped?: number } {
  if (raw == null || raw === '') {
    return { value: undefined };
  }
  if (!array) {
    return { value: Array.isArray(raw) ? (type ? INVALID : raw) : scalar(raw, type) };
  }
  const list = typeof raw === 'string' ? parseList(raw) : Array.isArray(raw) ? raw : [raw];
  if (list === INVALID) {
    return { value: INVALID };
  }
  const values = list.map((item) => scalar(item, type)).filter((item) => item !== INVALID);
  const dropped = list.length - values.length;
  // Nothing left of a list that had elements: as invalid as a single value of the wrong type.
  return { value: dropped && !values.length ? INVALID : values, dropped };
}

/** A JSON array, or else a comma-separated list. */
function parseList(raw: string): unknown[] | typeof INVALID {
  if (raw.trim().startsWith('[')) {
    try {
      const parsed = JSON.parse(raw);
      return Array.isArray(parsed) ? parsed : INVALID;
    } catch {
      return INVALID;
    }
  }
  return raw
    .split(',')
    .map((item) => item.trim())
    .filter((item) => item.length > 0);
}

function scalar(value: unknown, type: ClaimOptions['type']): unknown {
  if (!type || typeof value === type) {
    return value;
  }
  if (typeof value !== 'string') {
    return INVALID;
  }
  if (type === 'number') {
    const n = value.trim() === '' ? NaN : Number(value);
    return Number.isNaN(n) ? INVALID : n;
  }
  if (type === 'boolean') {
    return value === 'true' ? true : value === 'false' ? false : INVALID;
  }
  return INVALID;
}
