'use client';
import {motion,useScroll,useSpring,useReducedMotion} from 'motion/react';
export function ExperienceChrome(){
 const reduced=useReducedMotion();const {scrollYProgress}=useScroll();const scaleX=useSpring(scrollYProgress,{stiffness:90,damping:24,mass:.25});
 return <>
  {!reduced&&<motion.div className="scroll-progress" style={{scaleX}}/>}
  <div className="ambient"><i/><i/><i/></div>
 </>;
}
export function Reveal({children,className=''}:{children:React.ReactNode,className?:string}){
 const reduced=useReducedMotion();
 return <motion.div className={className} initial={reduced?false:{opacity:0,y:26,filter:'blur(8px)'}} whileInView={{opacity:1,y:0,filter:'blur(0px)'}} viewport={{once:true,margin:'-10%'}} transition={{duration:.65,ease:[.22,1,.36,1]}}>{children}</motion.div>
}
