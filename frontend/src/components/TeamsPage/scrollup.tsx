import { useEffect, useState } from "react";

export default function ScrollToTop() {
 
  const [isVisible, setIsVisible] = useState(false);


  useEffect(() => {
    const toggleVisibility = () => {
      
      if (window.scrollY >  240) {
        setIsVisible(true);
      } else {
        setIsVisible(false);
      }
    };

    window.addEventListener("scroll", toggleVisibility);
    return () => window.removeEventListener("scroll", toggleVisibility);
  }, []);

  const scrollToTop = () => {
    window.scrollTo({ top: 0, behavior: "smooth" });
  };

 if (!isVisible) return null;

  return (
    

    <button
      onClick={scrollToTop}
      className="
        fixed
        bottom-24
        mb-3
        right-3
        z-50
        h-12
        w-12
        rounded-full
        bg-[#C0C0C0]
        text-gray-800
        shadow-lg
        flex
        items-center
        justify-center
        hover:scale-110
        transition
      "
      aria-label="Scroll to top"
    >
      ↑
    </button>
    
  );
  
}
