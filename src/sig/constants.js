import { oids } from 'node-forge';
import { ED25519_OID } from '../keys/curve25519';

export const SIGNING_ALGO_RSA = { name: 'RSA', oid: oids.rsaEncryption };
export const SIGNING_ALGO_ED25519 = { name: 'ED25519', oid: ED25519_OID };

export const SIGNING_ALGOS = [SIGNING_ALGO_RSA.name, SIGNING_ALGO_ED25519.name];
