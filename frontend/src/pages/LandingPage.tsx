import React from "react";
import { useNavigate } from "react-router-dom";
import {
  FaInstagram,
  FaGlobe,
  FaClock,
  FaHome,
  FaInfoCircle,
  FaUsers,
  FaChartBar,
  FaFileAlt,
  FaCrown,
} from "react-icons/fa";

const LandingPage: React.FC = () => {
  const navigate = useNavigate();

  return (
    <div className="min-h-screen flex justify-center bg-[#F3F3F3]">
      
      {/* MOBILE FRAME */}
      <div
        className="relative w-[390px] min-h-screen overflow-y-auto pb-[120px]"
        style={{
          backgroundImage: "url(/Background.png)",
          backgroundSize: "440px 956px",
          backgroundRepeat: "repeat",
          backgroundPosition: "top center",
        }}
      >
        {/* SOFT OVERLAY */}
        <div className="absolute inset-0 bg-gradient-to-b from-white/50 via-white/30 to-white/40 pointer-events-none" />

        {/* CONTENT */}
        <div className="relative px-[20px] pt-[24px]">
          
          {/* LOGO + TAGLINE (NOW AT TOP) */}
          <div className="flex flex-col items-center mt-[24px]">
            <img
              src="/ghs-carnival-logo.png"
              alt="GHS Carnival Logo"
              className="h-[90px] object-contain"
            />

            <h1
              className="text-[#232165] text-center font-medium mt-[10px]"
              style={{
                fontFamily: "'Kdam Thmor Pro', sans-serif",
                fontSize: "20px",
              }}
            >
              Games, Glory & Hostel Stories
            </h1>
          </div>

          {/* HERO IMAGE */}
          <div className="mt-[28px] flex justify-center">
            <img
              src="/ghs.png"
              alt="GHS Carnival"
              className="w-[367px] h-[237px] object-cover rounded-[22px] shadow-lg"
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
            with jaw-dropping cultural performances and thrilling sporting events
            by our very own students.
          </p>

          {/* EVENT GALLERY */}
          <h3 className="mt-[28px] text-center text-[#FF8736] text-[26px] font-semibold">
            Event Gallery
          </h3>

          <div className="mt-[14px] grid grid-cols-3 gap-[10px]">
            <div className="h-[72px] rounded-[12px] bg-gray-300" />
            <div className="h-[72px] rounded-[12px] bg-gray-300" />
            <div className="h-[72px] rounded-[12px] bg-gray-300" />
          </div>

          {/* QUICK LINKS */}
          <div className="mt-[28px] bg-white rounded-[20px] shadow-lg px-[18px] py-[18px]">
            <h4 className="text-[18px] font-bold mb-[14px]">Quick Links</h4>

            <div className="space-y-[14px] text-[14px] font-semibold">
              <a
                href="https://www.instagram.com/ghs.carnival_muj/"
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center gap-[12px] hover:text-[#FF8736]"
              >
                <FaInstagram className="text-[20px] text-pink-500" />
                <span>GHS Carnival’s Official Page</span>
              </a>

              <div
                onClick={() => navigate("/guidelines")}
                className="flex items-center gap-[12px] cursor-pointer hover:text-[#FF8736]"
              >
                <FaGlobe className="text-[20px] text-blue-500" />
                <span>Guidelines / Rulebook</span>
              </div>

              <div
                onClick={() => navigate("/live-scores")}
                className="flex items-center gap-[12px] cursor-pointer hover:text-[#FF8736]"
              >
                <FaClock className="text-[20px] text-yellow-500" />
                <span>Cultural Events Updates</span>
              </div>
            </div>
          </div>
        </div>

        {/* FIXED BOTTOM NAV */}
        <div className="fixed bottom-0 left-1/2 -translate-x-1/2 w-[390px] bg-white border-t py-[10px] z-50">
          <div className="flex justify-around text-[11px] text-gray-500">
            <NavItem icon={<FaHome />} label="Home" active onClick={() => navigate("/")} />
            <NavItem icon={<FaInfoCircle />} label="About" onClick={() => navigate("/about")} />
            <NavItem icon={<FaCrown />} label="Block Captains" onClick={() => navigate("/hostel-blocks")} />
            <NavItem icon={<FaChartBar />} label="Live Scores" onClick={() => navigate("/live-scores")} />
            <NavItem icon={<FaFileAlt />} label="Guidelines" onClick={() => navigate("/guidelines")} />
            <NavItem icon={<FaUsers />} label="Dev Team" onClick={() => navigate("/teams")} />
          </div>
        </div>
      </div>
    </div>
  );
};

/* 🔹 BOTTOM NAV ITEM */
const NavItem = ({
  icon,
  label,
  active = false,
  onClick,
}: {
  icon: React.ReactNode;
  label: string;
  active?: boolean;
  onClick?: () => void;
}) => (
  <div
    onClick={onClick}
    className={`flex flex-col items-center cursor-pointer transition-colors duration-200 ${
      active ? "text-[#FF8736]" : "text-gray-500 hover:text-[#FF8736]"
    }`}
  >
    <div className="text-[18px]">{icon}</div>
    {label}
  </div>
);

export default LandingPage;

