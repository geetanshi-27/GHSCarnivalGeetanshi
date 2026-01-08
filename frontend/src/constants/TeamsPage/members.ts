import susanImg from "../../assets/TeamsPage/susan.png";


export type Team =
  | "all"
  | "core"
  | "tech"
  | "events"
  | "design"
  | "marketing";

export type Member = {
  id: number;
  name: string;
  team: Team;
  role: string;
  linkedin: string;
  email: string;
  image: string;
};





export const members: Member[]=[
  {
    id: 1,
    name: "Susan Johnson",
    team: "core",
    role: "Lead",
    linkedin:"https://www.linkedin.com/in/geetanshi-malik-b12221229/",
    email:"susan.johnson@gmai.com",
    image:susanImg

  },
  {
    id: 2,
    name: "Josh",
    team: "tech",
    role: "Developer",
    linkedin:"https://www.linkedin.com/in/geetanshi-malik-b12221229/",
    email:"susan.johnson@gmai.com",
    image:susanImg
  },
  {
    id: 3,
    name: "Graham",
    team: "tech",
    role: "Developer",
    linkedin:"https://www.linkedin.com/in/geetanshi-malik-b12221229/",
    email:"susan.johnson@gmai.com",
    image:susanImg
  },{
    id: 4,
    name: "Damon",
    team: "tech",
    role: "Developer",
    linkedin:"https://www.linkedin.com/in/geetanshi-malik-b12221229/",
    email:"susan.johnson@gmai.com",
    image: susanImg
  }
];