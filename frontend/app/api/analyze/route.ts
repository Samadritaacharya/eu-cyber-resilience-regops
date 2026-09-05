import {screen} from '../../../lib/engine';
import {validatePayload} from '../../../lib/validation';
const LIMIT=64_000;
export async function POST(req:Request){
 const len=Number(req.headers.get('content-length')||0);if(len>LIMIT)return Response.json({error:'Payload too large'},{status:413});
 let raw='';try{raw=await req.text()}catch{return Response.json({error:'Body read failed'},{status:400})}
 if(raw.length>LIMIT)return Response.json({error:'Payload too large'},{status:413});
 let body:unknown;try{body=JSON.parse(raw)}catch{return Response.json({error:'Malformed JSON'},{status:400})}
 try{const input=validatePayload(body);return Response.json({screening:screen(input),report_status:'DRAFT_REQUIRES_HUMAN_APPROVAL'})}
 catch(e){return Response.json({error:e instanceof Error?e.message:'Validation failed'},{status:422})}
}
