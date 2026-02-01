import React from "react";
import { useNavigate } from "react-router-dom";
import {
  FaInstagram,
  FaGlobe,
  FaClock,
  FaChartBar,
} from "react-icons/fa";

const LandingPage: React.FC = () => {
  const navigate = useNavigate();

  return (
    <div className="min-h-screen flex justify-center bg-[#F3F3F3]">
      {/* ANIMATION KEYFRAMES - UPDATED TO PLAY ONCE */}
      <style>
        {`
          @keyframes floatOnce {
            0% { transform: translateY(20px); opacity: 0; }
            100% { transform: translateY(0px); opacity: 1; }
          }
          .animate-float-once {
            animation: floatOnce 1.2s ease-out forwards;
          }
        `}
      </style>

      {/* MOBILE/DESKTOP RESPONSIVE FRAME */}
      <div
        className="relative w-full min-h-screen overflow-y-auto bg-[#F3F3F3]"
        style={{
          backgroundImage: "url(/Background.png)",
          backgroundSize: "cover",
          backgroundRepeat: "no-repeat",
          backgroundPosition: "top center",
        }}
      >
        {/* SOFT OVERLAY (reduced opacity) */}
        <div className="absolute inset-0 bg-gradient-to-b from-white/30 via-white/25 to-white/35 pointer-events-none" />

        {/* CONTENT */}
        <div className="relative z-10 px-[20px] md:px-[40px] lg:px-[80px] xl:px-[120px] pt-[24px] md:pt-[40px] lg:pt-[60px] max-w-screen mx-auto">
          {/* LOGO + TAGLINE */}
          <div className="flex flex-col items-center mt-[12px] md:mt-[24px] lg:mt-[36px]">
            <img
              src="/ghs_carnival_logo.png"
              alt="GHS Carnival Logo"
              className="h-[70px] md:h-[100px] lg:h-[130px] xl:h-[150px] object-contain drop-shadow-md animate-float-once"
            />

            <h1
              className="text-[#232165] text-center font-medium mt-[6px] md:mt-[12px] lg:mt-[18px] text-[16px] md:text-[20px] lg:text-[26px] xl:text-[32px]"
              style={{
                fontFamily: "'Kdam Thmor Pro', sans-serif",
              }}
            >
              Games, Glory & Hostel Stories
            </h1>
          </div>

          {/* HERO IMAGE */}
          <div className="mt-[16px] md:mt-[24px] lg:mt-[32px] flex justify-center">
            <img
              src="/ghs.png"
              alt="GHS Carnival"
              className="w-full max-w-[330px] md:max-w-[500px] lg:max-w-[700px] xl:max-w-[800px] h-auto object-cover rounded-[16px] shadow-lg"
            />
          </div>

          {/* DOTS */}
          <div className="flex justify-center gap-[6px] mt-[10px]">
            <span className="w-[6px] h-[6px] rounded-full bg-[#FF8736]" />
            <span className="w-[6px] h-[6px] rounded-full bg-gray-300" />
            <span className="w-[6px] h-[6px] rounded-full bg-gray-300" />
          </div>

          {/* TITLE */}
          <h2
            className="mt-[12px] md:mt-[18px] lg:mt-[28px] text-center text-[#FF8736] text-[22px] md:text-[28px] lg:text-[36px] xl:text-[42px]"
            style={{ fontFamily: "'Kdam Thmor Pro', sans-serif" }}
          >
            The Annual Carnival
          </h2>

          {/* DESCRIPTION */}
          <p
            className="mt-[8px] md:mt-[12px] lg:mt-[18px] text-center text-[12px] md:text-[14px] lg:text-[16px] xl:text-[18px] leading-[18px] md:leading-[22px] lg:leading-[26px] xl:leading-[30px] text-[#2F2F2F] max-w-[650px] mx-auto"
            style={{ fontFamily: "'Kdam Thmor Pro', sans-serif" }}
          >
            Returning back in 2026, the annual GHS Carnival is better than ever,
            with jaw-dropping cultural performances and thrilling sporting events
            by our very own students.
          </p>

          {/* EVENT GALLERY */}
          <h3 className="mt-[18px] md:mt-[26px] lg:mt-[36px] text-center text-[#FF8736] text-[22px] md:text-[28px] lg:text-[36px] xl:text-[42px] font-semibold">
            Event Gallery
          </h3>

          <div className="mt-[10px] md:mt-[16px] lg:mt-[24px] grid grid-cols-3 md:grid-cols-4 lg:grid-cols-6 xl:grid-cols-8 gap-[8px] md:gap-[12px] lg:gap-[14px] xl:gap-[18px] max-w-full mx-auto">
            <div className="h-[60px] md:h-[80px] lg:h-[100px] xl:h-[120px] rounded-[10px] bg-gray-300" />
            <div className="h-[60px] md:h-[80px] lg:h-[100px] xl:h-[120px] rounded-[10px] bg-gray-300" />
            <div className="h-[60px] md:h-[80px] lg:h-[100px] xl:h-[120px] rounded-[10px] bg-gray-300" />
            <div className="h-[60px] md:h-[80px] lg:h-[100px] xl:h-[120px] rounded-[10px] bg-gray-300 hidden md:block" />
            <div className="h-[60px] md:h-[80px] lg:h-[100px] xl:h-[120px] rounded-[10px] bg-gray-300 hidden lg:block" />
            <div className="h-[60px] md:h-[80px] lg:h-[100px] xl:h-[120px] rounded-[10px] bg-gray-300 hidden lg:block" />
            <div className="h-[60px] md:h-[80px] lg:h-[100px] xl:h-[120px] rounded-[10px] bg-gray-300 hidden xl:block" />
            <div className="h-[60px] md:h-[80px] lg:h-[100px] xl:h-[120px] rounded-[10px] bg-gray-300 hidden xl:block" />
          </div>

          {/* QUICK LINKS */}
          <div className="mt-[18px] md:mt-[28px] lg:mt-[36px] mb-[100px] md:mb-[120px] lg:mb-[150px] bg-white rounded-[16px] shadow-lg px-[14px] md:px-[24px] lg:px-[36px] xl:px-[48px] py-[14px] md:py-[20px] lg:py-[32px] max-w-[800px] mx-auto">
            <h4 className="text-[16px] md:text-[18px] lg:text-[22px] xl:text-[26px] font-bold mb-[12px] md:mb-[16px] lg:mb-[24px]">Quick Links</h4>

            <div className="space-y-[10px] md:space-y-[14px] lg:space-y-[18px] text-[12px] md:text-[14px] lg:text-[16px] xl:text-[18px] font-semibold">
              <a
                href="https://www.instagram.com/ghs.carnival_muj/"
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center gap-[12px] md:gap-[16px] hover:text-[#FF8736] transition-colors"
              >
                <FaInstagram className="text-[20px] md:text-[26px] lg:text-[32px] text-pink-500" />
                <span>GHS Carnival’s Official Page</span>
              </a>

              <div
                onClick={() => navigate("/guidelines")}
                className="flex items-center gap-[12px] md:gap-[16px] cursor-pointer hover:text-[#FF8736] transition-colors"
              >
                <FaGlobe className="text-[20px] md:text-[26px] lg:text-[32px] text-blue-500" />
                <span>Guidelines / Rulebook</span>
              </div>

              <div
                onClick={() => navigate("/live-scores")}
                className="flex items-center gap-[12px] md:gap-[16px] cursor-pointer hover:text-[#FF8736] transition-colors"
              >
                <FaClock className="text-[20px] md:text-[26px] lg:text-[32px] text-yellow-500" />
                <span>Cultural Events Updates</span>
              </div>
            </div>
          </div>
        </div>

        {/* FLOATING LIVE SCORES CAPSULE - RESPONSIVE POSITIONING */}
        <div
          onClick={() => navigate("/live-scores")}
          className="fixed bottom-[80px] left-1/2 -translate-x-1/2
                     md:bottom-[100px] lg:bottom-[120px] xl:bottom-[140px]
                     px-[18px] md:px-[28px] lg:px-[36px] xl:px-[44px] h-[48px] md:h-[56px] lg:h-[64px] xl:h-[72px] rounded-full
                     bg-[#FF8736] text-white opacity-75 hover:opacity-100
                     flex items-center gap-[8px] md:gap-[12px] lg:gap-[16px]
                     shadow-lg cursor-pointer
                     active:scale-95 transition-all z-50"
        >
          <FaChartBar className="text-[18px] md:text-[22px] lg:text-[28px] xl:text-[32px]" />
          <span className="text-[13px] md:text-[15px] lg:text-[18px] xl:text-[20px] font-semibold">Live Score</span>
        </div>

      </div>
    </div>
  );
};

export default LandingPage;
