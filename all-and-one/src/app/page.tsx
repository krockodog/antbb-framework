import { HomeIntro } from "@/components/home-intro";
import { LegalNote } from "@/components/legal-note";
import { QueenCards } from "@/components/queen-cards";
import { SiteHeader } from "@/components/site-header";

export default function Home() {
  return (
    <main className="relative min-h-dvh overflow-hidden">
      <div className="atmosphere" aria-hidden="true">
        <span className="orb orb-red" />
        <span className="orb orb-blue" />
        <span className="orb orb-yellow" />
      </div>
      <div className="grain" aria-hidden="true" />
      <div className="relative z-10 mx-auto flex min-h-dvh max-w-6xl flex-col px-5 py-6 md:px-8">
        <SiteHeader />
        <HomeIntro />
        <QueenCards />
        <footer className="mt-auto pt-12 pb-2">
          <LegalNote />
          <p className="mt-4 text-sm tracking-wide text-foreground/70">
            All and One - RED-BLUE-Yellow-Ant-Team
          </p>
        </footer>
      </div>
      <script src="/static/hub-real.js?v=202610240215" defer />
    </main>
  );
}
