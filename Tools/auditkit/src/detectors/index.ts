import type { Detector } from '../types.ts';
import { reentrancyDetector } from './reentrancy.ts';
import { uncheckedCallDetector } from './unchecked-call.ts';
import { txOriginDetector } from './tx-origin.ts';
import { delegatecallDetector } from './delegatecall.ts';
import { selfdestructDetector } from './selfdestruct.ts';
import { weakRandomnessDetector } from './weak-randomness.ts';
import { unprotectedInitializerDetector } from './unprotected-initializer.ts';
import { integerOverflowDetector } from './integer-overflow.ts';
import { accessControlDetector } from './access-control.ts';

export const detectors: Record<string, Detector> = {
  reentrancy: reentrancyDetector,
  'unchecked-call': uncheckedCallDetector,
  'tx-origin': txOriginDetector,
  delegatecall: delegatecallDetector,
  selfdestruct: selfdestructDetector,
  'weak-randomness': weakRandomnessDetector,
  'unprotected-initializer': unprotectedInitializerDetector,
  'integer-overflow': integerOverflowDetector,
  'access-control': accessControlDetector,
};
