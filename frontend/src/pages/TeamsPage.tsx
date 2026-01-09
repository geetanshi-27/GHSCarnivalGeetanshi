import { useState } from "react";

import Header from "../components/TeamsPage/Header";
import TeamTabs from "../components/TeamsPage/teamtabs";
import MemberCard from "../components/TeamsPage/MemberCard";
import ScrollToTop from "../components/TeamsPage/scrollup";

import { members } from "../constants/TeamsPage/members";
import bg from "../assets/TeamsPage/background.svg";

export type Team =
  | "all"
  | "core"
  | "tech"
  | "events"
  | "design"
  | "marketing";



export default function TeamsPage() {


  const [activeTab, setActiveTab] = useState<Team>("all");

  const filteredMembers =
    activeTab === "all"
      ? members
      : members.filter((member) => member.team === activeTab);


  return (

  <>
    <ScrollToTop />
  

  <div data-page="teams" className="relative min-h-screen w-full overflow-x-hidden">
       
      <div
          className="fixed inset-0 -z-10 bg-no-repeat bg-center bg-cover"
          style={{
            backgroundImage: `url(${bg})`,
            minHeight: "100vh",
          }}
        />

      <div className="pb-24 pt-6">
          <Header />

          <div className="p-3 flex flex-col items-center">
            <h2
              className="text-[30px] font-kdam mb-7 text-center
              bg-gradient-to-r
              from-[#FFBE86]
              to-[#8D89FF]
              bg-clip-text
              text-transparent"
            >
              MEET THE TEAM
            </h2>


            <div className="w-full max-w-sm">

            <TeamTabs onTabChange={setActiveTab} />

            </div>
            


            <div className="flex flex-col items-center">
              <div className="w-full max-w-sm min-h-[80vh] space-y-14">
                {filteredMembers.map((member) => (
                  <MemberCard
                    key={member.id}
                    member={member}
                    activeTab={activeTab}
                  />
                ))}
              </div>

            </div>
          </div>
      </div>
  </div>

  </>
  )
}
