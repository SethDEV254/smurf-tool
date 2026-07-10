import type { Detector, Finding } from '../types.ts';
import { contractsOf, functionsOf, lineOf } from '../ast.ts';
import { hasSenderCheckModifierOrGuard } from './shared.ts';

const SENSITIVE_NAME_RE =
  /^(withdraw|mint|burn|setowner|transferownership|upgrade|upgradeto|pause|unpause|setfee|setfees|rescue|sweep|drain|setadmin|setprice|setoracle|emergencywithdraw)/i;

/** Flags publicly reachable, sensitively-named functions with no visible modifier or sender check. */
export const accessControlDetector: Detector = ({ filePath, ast }) => {
  const findings: Finding[] = [];

  for (const contract of contractsOf(ast)) {
    for (const fn of functionsOf(contract)) {
      if (!fn.name || !SENSITIVE_NAME_RE.test(fn.name)) continue;
      if (fn.visibility === 'private' || fn.visibility === 'internal') continue;
      if (!fn.body) continue;
      if (hasSenderCheckModifierOrGuard(fn)) continue;

      findings.push({
        id: `access-control:${contract.name}:${fn.name}:${lineOf(fn)}`,
        detector: 'access-control',
        severity: 'high',
        title: `Sensitive function without access control: ${contract.name}.${fn.name}`,
        description:
          `'${fn.name}(...)' is externally/publicly reachable, named like a privileged operation, ` +
          `and has no modifier or visible 'require(msg.sender == ...)'/'onlyOwner'-style guard in its ` +
          `body. Confirm this is intentionally open, otherwise anyone can call it.`,
        file: filePath,
        line: lineOf(fn),
        contract: contract.name,
        function: fn.name,
        exploitTemplate: 'access-control-hijack',
      });
    }
  }

  return findings;
};
