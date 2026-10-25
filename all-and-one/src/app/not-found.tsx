import Link from "next/link";

import { SiteHeader } from "@/components/site-header";
import { buttonVariants } from "@/components/ui/button";
import { cn } from "cn";

export default function NotFound() {
  return (
    <main className="mx-auto flex min-h-dvh max-w-3xl flex-col px-5 py-6">
      <SiteHeader />
      <section className="py-20">
        <p className="text-[0.72rem] tracking-[0.22em] text-[var(--gold)] uppercase">
          Kein Pfad
        </p>
        <h1 className="font-heading mt-3 text-5xl">Diese Route kenne ich nicht.</h1>
        <p className="mt-4 max-w-xl text-foreground/75">
          Rot, Blau und Gelb bleiben auf ihren eigenen Wegen. Der Hub und der
          Neural Brain sind die sicheren Eingänge.
        </p>
        <div className="mt-8 flex gap-3">
          <Link href="/" className={cn(buttonVariants({ size: "lg" }), "h-10 px-4")}>
            Zum Hub
          </Link>
          <Link
            href="/brain"
            className={cn(buttonVariants({ variant: "outline", size: "lg" }), "h-10 px-4")}
          >
            Neural Brain
          </Link>
        </div>
      </section>
    </main>
  );
}
