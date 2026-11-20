import {
  ApprovalWorkflow,
  AuditPreview,
  FinalCta,
  GovernanceBar,
  GovernanceProvider,
  LiveSecurityStatus,
  RiskClasses,
  WorkflowSteps,
} from "@/components/governance";
import { HomeIntro } from "@/components/home-intro";
import { LegalNote } from "@/components/legal-note";
import { QueenCards } from "@/components/queen-cards";
import { SiteHeader } from "@/components/site-header";

// Reihenfolge (Mark): Hero+CTA (mit Security Contract) → Rechtshinweis →
// Live Security Status → drei Königinnen → Freigabe-Workflow + Risikoklassen →
// Workflow → Audit/Oversight → CTA. Statusleiste fest unter dem Header.
export default function Home() {
  return (
    <main className="relative min-h-dvh overflow-hidden">
      <div className="atmosphere" aria-hidden="true">
        <span className="orb orb-red" />
        <span className="orb orb-blue" />
        <span className="orb orb-yellow" />
      </div>
      <div className="grain" aria-hidden="true" />
      <GovernanceProvider>
        <div className="gov-sticky relative z-20">
          <SiteHeader />
          <GovernanceBar />
        </div>
        <div className="home-shell relative z-10 mx-auto flex flex-col">
          <HomeIntro />
          <section className="gov-legal" aria-label="Rechtshinweis">
            <LegalNote />
          </section>
          <LiveSecurityStatus />
          <QueenCards />
          <ApprovalWorkflow />
          <RiskClasses />
          <WorkflowSteps />
          <AuditPreview />
          <FinalCta />
          <footer className="mt-auto pt-12 pb-2">
            <p className="text-sm tracking-wide text-foreground/70">All and One - RED-BLUE-Yellow-Ant-Team</p>
          </footer>
        </div>
      </GovernanceProvider>
      <script src="/static/hub-real.js?v=202611201500" defer />
    </main>
  );
}
