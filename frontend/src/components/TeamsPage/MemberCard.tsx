import {teamColors} from "../../constants/TeamsPage/teamColors";
import { FaLinkedin, FaEnvelope } from "react-icons/fa";
  

type Team =
  | "all"
  | "core"
  | "tech"
  | "events"
  | "design"
  | "marketing";

type Member = {
  id: number;
  name: string;
  team: Team;
  role: string;
  linkedin: string;
  email: string;
  image:string;
};

type MemberCardProps = {
  member: Member;
  activeTab: Team;
};

  


function MemberCard({ member, activeTab }:MemberCardProps) {

 

  return (
    
  <>
    <div className="h-[420px]
      relative
      w-[250px]
      mx-auto
      rounded-2xl
      bg-white
      shadow-lg
      flex
      flex-col
      items-center
      p-6
      flex-shrink-0
      overflow-hidden
      ">
      

      <div className="relative z-10 flex flex-col items-center text-center">
      <h3 className="text-2xl font-kdam text-transform: uppercase">{member.name}</h3>
       <p
      className={`
        font-kdam transition-colors text-transform: uppercase
        ${activeTab===member.team ? teamColors[member.team] : "text-gray-500"}
      `}
    >
      {member.role}
    </p>


    {/* Icons row */}
      <div className="flex gap-5 mt-4">
        {/* LinkedIn */}
        <a
          href={member.linkedin}
          target="_blank"
          rel="noopener noreferrer"
          className="text-[#0A66C2] hover:bg-gray-100 active:scale-95 transition"
          aria-label="LinkedIn">

          <FaLinkedin size={24} />
        </a>
        
        <a
          href={`mailto:${member.email}`}
          className="
            text-gray-700
            
            rounded-full
            hover:bg-gray-100
            active:scale-95">
          <FaEnvelope size={24} />
        </a>

        
      </div>
      </div>

      <img
          src={member.image}
          alt={member.name}
          className="
            absolute
            bottom-0
            left-1/2
            -translate-x-1/2
            w-[90%]
            object-contain
            
            pointer-events-none
          "
        />

      

    
    </div>

   
   </>
    
  );
}
export default MemberCard