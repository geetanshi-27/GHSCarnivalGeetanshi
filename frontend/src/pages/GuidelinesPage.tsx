import React from "react";
import { FaFileAlt, FaCheckCircle } from "react-icons/fa";

export default function GuidelinesPage() {
  return (
    <div className="min-h-screen flex justify-center bg-[#F3F3F3] pb-[100px]" style={{
      backgroundImage: "url(/Background.png)",
      backgroundSize: "cover",
      backgroundRepeat: "no-repeat",
      backgroundPosition: "top center",
      backgroundAttachment: "fixed",
    }}>
      {/* ANIMATION KEYFRAMES */}
      <style>
        {`
          @keyframes floatOnce {
            0% { transform: translateY(20px); opacity: 0; }
            100% { transform: translateY(0px); opacity: 1; }
          }
          .animate-float-once {
            animation: floatOnce 1.2s ease-out forwards;
          }
          @keyframes pulse-gentle {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.6; }
          }
          .animate-pulse-gentle {
            animation: pulse-gentle 2s ease-in-out infinite;
          }
        `}
      </style>

      {/* SOFT OVERLAY */}
      {/* <div className="absolute inset-0 bg-gradient-to-b from-white/30 via-white/25 to-white/35 pointer-events-none" /> */}

      {/* CONTENT */}
      <div className="relative z-10 w-full max-w-[900px] px-[20px] md:px-[40px] lg:px-[80px] xl:px-[120px] pt-[40px] md:pt-[60px] lg:pt-[100px]">
        {/* HEADER */}
        <header className="py-2 flex justify-center mb-4">
          <img 
            src="/ghs_carnival_logo.png" 
            alt="GHS Carnival logo"
            className="h-12 md:h-14 w-auto object-contain"
          />
        </header>
        <div className="flex flex-col items-center text-center">
          <div className="mb-[20px] md:mb-[30px] lg:mb-[40px] animate-float-once">
            <FaFileAlt className="text-[48px] md:text-[64px] lg:text-[80px] text-[#FF8736] mx-auto" />
          </div>

          <h1
            className="text-[28px] md:text-[36px] lg:text-[48px] xl:text-[56px] font-bold text-[#232165] mb-[12px] md:mb-[20px]"
            style={{ fontFamily: "'Kdam Thmor Pro', sans-serif" }}
          >
            Guidelines & Rulebook
          </h1>

          <p className="text-[16px] md:text-[18px] lg:text-[20px] text-[#666] mb-[20px] md:mb-[30px] lg:mb-[40px]">
            <span className="inline-block px-[12px] md:px-[16px] py-[6px] md:py-[8px] bg-[#FFF4E6] rounded-full text-[#FF8736] font-semibold">
              Coming Soon
            </span>
          </p>

          <div className="text-center max-w-[700px] mb-[40px] md:mb-[60px] lg:mb-[80px]">
            <h2
              className="text-[20px] md:text-[24px] lg:text-[32px] text-[#FF8736] mb-[16px] md:mb-[24px]"
              style={{ fontFamily: "'Kdam Thmor Pro', sans-serif" }}
            >
              Competition Guidelines
            </h2>
            <p className="text-[14px] md:text-[16px] lg:text-[18px] leading-[24px] md:leading-[28px] lg:leading-[32px] text-[#2F2F2F]">
              We're preparing comprehensive guidelines and rulebooks for all events. These will include detailed information about eligibility criteria, event formats, scoring systems, and conduct expectations.
            </p>
          </div>

          {/* FEATURES COMING */}
          <div className="bg-white rounded-[20px] shadow-lg p-[24px] md:p-[32px] lg:p-[48px] max-w-[700px] w-full mb-[40px] md:mb-[60px]">
            <h3
              className="text-[20px] md:text-[24px] lg:text-[28px] text-[#232165] font-bold mb-[24px] md:mb-[32px]"
              style={{ fontFamily: "'Kdam Thmor Pro', sans-serif" }}
            >
              What's Coming
            </h3>

            <div className="space-y-[16px] md:space-y-[20px] lg:space-y-[24px]">
              <div className="flex items-start gap-[12px] md:gap-[16px]">
                <FaCheckCircle className="text-[20px] md:text-[24px] text-[#FF8736] flex-shrink-0 mt-[2px] md:mt-[4px]" />
                <div>
                  <h4 className="text-[16px] md:text-[18px] lg:text-[20px] font-semibold text-[#232165]">
                    Sports Events Rules
                  </h4>
                  <p className="text-[14px] md:text-[15px] lg:text-[16px] text-[#666] mt-[4px]">
                    Detailed rulebooks for all sporting competitions
                  </p>
                </div>
              </div>

              <div className="flex items-start gap-[12px] md:gap-[16px]">
                <FaCheckCircle className="text-[20px] md:text-[24px] text-[#FF8736] flex-shrink-0 mt-[2px] md:mt-[4px]" />
                <div>
                  <h4 className="text-[16px] md:text-[18px] lg:text-[20px] font-semibold text-[#232165]">
                    Cultural Event Guidelines
                  </h4>
                  <p className="text-[14px] md:text-[15px] lg:text-[16px] text-[#666] mt-[4px]">
                    Requirements and expectations for cultural performances
                  </p>
                </div>
              </div>

              <div className="flex items-start gap-[12px] md:gap-[16px]">
                <FaCheckCircle className="text-[20px] md:text-[24px] text-[#FF8736] flex-shrink-0 mt-[2px] md:mt-[4px]" />
                <div>
                  <h4 className="text-[16px] md:text-[18px] lg:text-[20px] font-semibold text-[#232165]">
                    Scoring & Rankings
                  </h4>
                  <p className="text-[14px] md:text-[15px] lg:text-[16px] text-[#666] mt-[4px]">
                    Comprehensive scoring systems and ranking criteria
                  </p>
                </div>
              </div>

              <div className="flex items-start gap-[12px] md:gap-[16px]">
                <FaCheckCircle className="text-[20px] md:text-[24px] text-[#FF8736] flex-shrink-0 mt-[2px] md:mt-[4px]" />
                <div>
                  <h4 className="text-[16px] md:text-[18px] lg:text-[20px] font-semibold text-[#232165]">
                    Conduct & Discipline
                  </h4>
                  <p className="text-[14px] md:text-[15px] lg:text-[16px] text-[#666] mt-[4px]">
                    Code of conduct and disciplinary policies
                  </p>
                </div>
              </div>
            </div>
          </div>

          {/* COMING SOON MESSAGE */}
          <div className="text-center">
            <p className="text-[14px] md:text-[16px] lg:text-[18px] text-[#666] mb-[12px] md:mb-[16px]">
              📋 Guidelines will be available soon
            </p>
            <p className="text-[12px] md:text-[14px] lg:text-[16px] text-[#999]">
              Stay tuned for updates. Check back soon!
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

