import cases from '../../../lib/evaluation_cases.json';
import {screen} from '../../../lib/engine';
export async function GET(){
 let passed=0;
 for(const c of cases){const r=screen(c.input as never);if(r.cra_status===c.expected.cra_status&&r.nis2_status===c.expected.nis2_status&&r.decision===c.expected.decision)passed++}
 return Response.json({cases:cases.length,passed,accuracy:passed/cases.length});
}
