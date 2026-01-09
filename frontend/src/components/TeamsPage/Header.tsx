import logo from "../../assets/TeamsPage/ghs-logo.svg";

function Header() {
  return (
    <header className="py-2 flex justify-center">
      <a
        href="/"
        className="flex items-center gap-1
        "
      >
        <img
          src={logo}
          alt="GHS Carnival Logo"
          className="h-[46px] w-[130px]"
        />

        <h1 className="text-[42px] text-[#302054] font-garamond tracking-wide pt-1">
          CARNIVAL
        </h1>
      </a>

    </header>
  );
}

export default Header;
