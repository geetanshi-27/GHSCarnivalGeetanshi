import React from "react";
import {
  FaInstagram,
  FaGlobe,
  FaClock,
  FaHome,
  FaInfoCircle,
  FaUsers,
  FaChartBar,
  FaFileAlt,
} from "react-icons/fa";

const LandingPage = () => {
  return (
    <div className="min-h-screen flex justify-center bg-[#F3F3F3]">
      {/* MOBILE FRAME */}
      <div
        className="relative w-[390px] min-h-screen overflow-y-auto pb-[110px]"
        style={{
          backgroundImage: "url(/Background.png)",
          backgroundSize: "440px 956px",
          backgroundRepeat: "repeat",
          backgroundPosition: "top center",
        }}
      >
        {/* SOFT COLOR-CORRECTION OVERLAY (FIXES BRIGHTNESS) */}
        <div className="absolute inset-0 bg-gradient-to-b from-white/50 via-white/30 to-white/40 pointer-events-none" />

        {/* CONTENT */}
        <div className="relative px-[20px] pt-[24px]">
          {/* TOP LOGO */}
          <div className="flex justify-center">
            <img
              src="/ghs-carnival-logo.png"
              alt="GHS Carnival"
              className="h-[100px] object-contain"
              style={{ marginTop: "30vh" }}
            />
          </div>


          <div 
          style={{
            display : "flex",
            justifyContent: "center"
          }}>
          <h1
            className="text-[#232165]"
            style={{ fontFamily: "'Kdam thmor pro', sans-serif", fontSize: "20px", paddingBottom: "50vh", display : "flex" , textAlign:"center", fontWeight: 500 }}

            >
              Games, Glory & Hostel Stories
            </h1>
          </div>
          {/* HERO IMAGE */}
          <div className="mt-[20px] flex justify-center">
            <img
              src="/ghs.png"
              alt="GHS Carnival"
              className="w-[367px] h-[237px] object-cover rounded-[22px] shadow-lg"
            />
          </div>

          {/* DOT INDICATORS */}
          <div className="flex justify-center gap-[6px] mt-[10px]">
            <span className="w-[6px] h-[6px] rounded-full bg-[#FF8736]" />
            <span className="w-[6px] h-[6px] rounded-full bg-gray-300" />
            <span className="w-[6px] h-[6px] rounded-full bg-gray-300" />
          </div>

          {/* TITLE */}
          <h2
            className="mt-[18px] text-center text-[#FF8736] text-[26px]"
            style={{ fontFamily: "'Kdam Thmor Pro', sans-serif" }}
          >
            The Annual Carnival
          </h2>

          {/* DESCRIPTION */}
          <p
            className="mt-[12px] text-center text-[14px] leading-[22px] text-[#2F2F2F]"
            style={{ fontFamily: "'Kdam Thmor Pro', sans-serif" }}
          >
            Returning back in 2026, the annual GHS Carnival is better than ever,
            with upcoming jaw-dropping cultural performances, to be presented by
            our very own students and thrilling sporting events.
          </p>

          {/* EVENT GALLERY */}
          <h3 className="mt-[24px] text-center text-[#FF8736] text-[26px] font-semibold">
            Event Gallery
          </h3>

          <div className="mt-[14px] grid grid-cols-3 gap-[10px]">
            <div className="h-[72px] rounded-[12px] bg-gray-300" />
            <div className="h-[72px] rounded-[12px] bg-gray-300" />
            <div className="h-[72px] rounded-[12px] bg-gray-300" />
          </div>

          {/* QUICK LINKS */}
          <div className="mt-[28px] bg-white rounded-[20px] shadow-lg px-[18px] py-[18px]">
            <h4 className="text-[18px] font-bold mb-[14px]">
              Quick Links
            </h4>

            <div className="space-y-[14px] text-[14px] font-semibold">
              <div className="flex items-center gap-[12px]">
                <FaInstagram className="text-[20px] text-pink-500" />
                <span>GHS CARNIVAL’s Official Page</span>
              </div>

              <div className="flex items-center gap-[12px]">
                <FaGlobe className="text-[20px] text-blue-500" />
                <span>Guidelines / Rulebook</span>
              </div>

              <div className="flex items-center gap-[12px]">
                <FaClock className="text-[20px] text-yellow-500" />
                <span>Cultural Events Updates</span>
              </div>
            </div>
          </div>
        </div>

        {/* FIXED BOTTOM NAV */}
        <div className="fixed bottom-0 left-1/2 -translate-x-1/2 w-[390px] bg-white border-t py-[10px] z-50">
          <div className="flex justify-around text-[11px] text-gray-500">
            <div className="flex flex-col items-center text-[#FF8736]">
              <FaHome className="text-[18px]" />
              Home
            </div>

            <div className="flex flex-col items-center">
              <FaInfoCircle className="text-[18px]" />
              About
            </div>

            <div className="flex flex-col items-center">
              <FaUsers className="text-[18px]" />
              Dev Team
            </div>

            <div className="flex flex-col items-center">
              <FaChartBar className="text-[18px]" />
              Live Score
            </div>

            <div className="flex flex-col items-center">
              <FaFileAlt className="text-[18px]" />
              Guidelines
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default LandingPage;

