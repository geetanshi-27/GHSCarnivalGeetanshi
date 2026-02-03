import React, { useState, useEffect, useCallback } from 'react';
import { Trophy, Users, Star, ChevronDown } from 'lucide-react';

const AboutPage: React.FC = () => {
  const [activeSlide, setActiveSlide] = useState(0);
  const [openFaq, setOpenFaq] = useState<number | null>(null);

  const carouselImages = [
    { url: './about/1.jpg', alt: 'Box Cricket Action' },
    { url: './about/2.jpg', alt: 'Box Cricket Action' },
    { url: './about/3.jpg', alt: 'Table Tennis Smash' },
    { url: './about/4.jpg', alt: 'Basket Ball'},
    { url: './about/5.jpg', alt: 'chess'},
    { url: './about/6.jpg', alt: 'Sqaush'},
  ];

  const nextSlide = useCallback(() => {
    setActiveSlide((prev) => (prev === carouselImages.length - 1 ? 0 : prev + 1));
  }, [carouselImages.length]);

  useEffect(() => {
    const interval = setInterval(nextSlide, 5000);
    return () => clearInterval(interval);
  }, [nextSlide]);

  return (
    <div className="min-h-screen text-gray-800 font-sans relative">
      
      {/* BACKGROUND LAYER - No Blur */}
      <div 
        className="fixed inset-0 -z-10 bg-no-repeat 
                   bg-[url('./Background.png')] 
                   bg-center bg-cover md:bg-fixed"
      />

      {/* Logo in Top Left */}
      <header className="py-2 flex justify-center relative z-20">
        <img 
          src="/ghs_carnival_logo.png" 
          alt="GHS Carnival Logo" 
          className="h-14 md:h-16 w-auto object-contain drop-shadow-lg"
        />
      </header>

      {/* 1. Header & Description Section */}
      <section className="max-w-4xl mx-auto pt-28 md:pt-40 px-6 text-center">
        <h1 
          className="text-5xl md:text-8xl font-kdam uppercase text-[#92400E] mb-10 tracking-tight drop-shadow-md"
        >
          About GHS Carnival
        </h1>
        <div className="bg-white/30 p-6 rounded-3xl inline-block">
            <p className="text-lg md:text-xl leading-relaxed text-gray-900 max-w-2xl mx-auto font-medium">
            The <span className="font-bold text-[#D97706]">GHS Carnival</span> is the ultimate celebration of sportsmanship, grit, and hostel brotherhood. 
            More than just a tournament, it’s where legends are born.
            </p>
        </div>
      </section>

      {/* 2. Stats/Highlights Section */}
      <section className="max-w-6xl mx-auto px-6 py-12 grid grid-cols-1 md:grid-cols-3 gap-6">
        {[
          { icon: Trophy, label: "5+ Sports", sub: "Cricket to Table Tennis" },
          { icon: Users, label: "10+ Blocks", sub: "Inter-Hostel Rivalry" },
          { icon: Star, label: "Live Engine", sub: "Instant Ball Updates" }
        ].map((item, idx) => (
          <div key={idx} className="bg-white/80 p-8 rounded-[2rem] border border-white/50 shadow-2xl flex flex-col items-center text-center">
            <div className="bg-[#D97706] p-4 rounded-2xl mb-4 shadow-lg">
              <item.icon className="text-white" size={32} />
            </div>
            <h3 className="font-bold text-2xl text-gray-900">{item.label}</h3>
            <p className="text-gray-600 mt-1 font-medium">{item.sub}</p>
          </div>
        ))}
      </section>

      {/* 3. Interactive Carousel Section */}
      <section className="max-w-5xl mx-auto px-6 mb-20">
        <div 
          onClick={nextSlide}
          className="relative overflow-hidden rounded-[2.5rem] border-[8px] border-white shadow-2xl aspect-[4/3] md:aspect-video cursor-pointer group"
        >
          {carouselImages.map((image, index) => (
            <div
              key={index}
              className={`absolute inset-0 transition-all duration-1000 ease-in-out transform ${
                index === activeSlide ? 'opacity-100 scale-100' : 'opacity-0 scale-110'
              }`}
            >
              <img src={image.url} alt={image.alt} className="w-full h-full object-cover" />
              <div className="absolute inset-0 bg-gradient-to-t from-black/80 via-transparent to-transparent" />
              <div className="absolute bottom-8 left-8">
                 <p className="text-white font-medium text-2xl md:text-3xl italic tracking-wide">
                    {image.alt}
                 </p>
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* 4. FAQs Section */}
      <section className="max-w-3xl mx-auto px-6 pb-32">
        <h2 
          style={{ fontFamily: "'Italiana', serif" }}
          className="text-4xl md:text-5xl text-center text-[#92400E] mb-10 drop-shadow-sm"
        >
          Common Questions
        </h2>
        <div className="space-y-4">
          {[
            { q: "How do I register my block team?", a: "Registrations are handled by your respective Block Sports Representative." },
            { q: "Where can I see the live standings?", a: "The 'Live Scores' tab on the homepage updates instantly." },
            { q: "Is there a prize for the overall champion?", a: "The block with the highest points wins the GHS Carnival Trophy." },
            { q: "How many sports would be played in the carnival?", a: "In total 11 sports would be played in the GHS Carnival." }
          ].map((faq, i) => (
            <div key={i} className="bg-white/90 rounded-2xl border border-orange-100 shadow-lg">
              <button 
                onClick={() => setOpenFaq(openFaq === i ? null : i)}
                className="w-full p-6 text-left flex justify-between items-center font-bold text-gray-800"
              >
                {faq.q}
                <ChevronDown className={`transition-transform duration-300 ${openFaq === i ? 'rotate-180' : ''}`} />
              </button>
              {openFaq === i && (
                <div className="px-6 pb-6 text-gray-700 leading-relaxed font-medium">
                  {faq.a}
                </div>
              )}
            </div>
          ))}
        </div>
      </section>
    </div>
  );
};

export default AboutPage;