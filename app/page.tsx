import type { Metadata } from "next";
import { OpsConsole } from "./ops-console";

export const metadata: Metadata = {
  title: { absolute: "Operation Portal" },
  description: "Trung tâm vận hành an toàn cho máy chủ Windows và Linux.",
};

export default function Home() {
  return <OpsConsole />;
}
