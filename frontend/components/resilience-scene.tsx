'use client';
import {Canvas,useFrame} from '@react-three/fiber';
import {useRef} from 'react';
import * as THREE from 'three';

function Core({risk}:{risk:number}){
 const ref=useRef<THREE.Mesh>(null);
 useFrame((state,delta)=>{if(ref.current){ref.current.rotation.x+=delta*.13;ref.current.rotation.y+=delta*.21;const s=1+Math.sin(state.clock.elapsedTime*1.6)*.035;ref.current.scale.setScalar(s)}});
 return <mesh ref={ref}>
   <icosahedronGeometry args={[1.25,3]}/>
   <meshStandardMaterial color={risk>75?'#ff6b6b':risk>50?'#f6c177':'#7ce7c5'} metalness={.65} roughness={.18} wireframe={false}/>
 </mesh>
}
function Ring({radius,speed}:{radius:number;speed:number}){
 const ref=useRef<THREE.Mesh>(null);useFrame((_,d)=>{if(ref.current)ref.current.rotation.z+=d*speed});
 return <mesh ref={ref} rotation={[Math.PI/2,0,0]}><torusGeometry args={[radius,.018,8,96]}/><meshBasicMaterial color="#7aa2ff" transparent opacity={.55}/></mesh>
}
function Node({p,label}:{p:[number,number,number],label:string}){
 return <group position={p}><mesh><sphereGeometry args={[.09,20,20]}/><meshStandardMaterial color="#b9c7ff" emissive="#4a66ff" emissiveIntensity={1.5}/></mesh></group>
}
export function ResilienceScene({risk=68}:{risk?:number}){
 const nodes:[[number,number,number],string][]=[
  [[-2.2,.8,0],'SBOM'],[[2.2,.9,0],'CVE'],[[-2,-1.1,.2],'CRA'],[[2,-1.2,.2],'NIS2'],[[0,2,.1],'Evidence'],[[0,-2,.1],'Approval']
 ];
 return <div className="scene-wrap">
  <Canvas camera={{position:[0,0,6.2],fov:42}} dpr={[1,1.5]}>
    <ambientLight intensity={.8}/><pointLight position={[3,4,5]} intensity={15}/><pointLight position={[-4,-2,3]} intensity={8} color="#4f6bff"/>
    <Core risk={risk}/><Ring radius={1.8} speed={.11}/><Ring radius={2.35} speed={-.07}/>
    {nodes.map(([p,l])=><Node key={l} p={p} label={l}/>)}
  </Canvas>
  <div className="scene-label"><span/> policy + evidence graph</div>
 </div>
}
