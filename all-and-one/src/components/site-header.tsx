import Link from "next/link";

const LINKS = [
  { href: "/", label: "Scope-Manager" },
  { href: "/red", label: "🔴 Red Queen" },
  { href: "/blue", label: "🛡 Blue Queen" },
  { href: "/yellow", label: "🟡 Yellow Queen" },
  { href: "/wlan", label: "📡 WLAN" },
  { href: "/brain", label: "🧠 Neuronales Gehirn" },
  { href: "/assets", label: "🔒 Eigene Assets" },
  { href: "/history", label: "🗂️ Historie" },
];

export function SiteHeader() {
  return (
    <header className="flex flex-wrap items-center justify-between gap-4">
      <Link href="/" className="group block">
        <span className="block text-[0.7rem] tracking-[0.22em] text-[var(--gold)] uppercase">
          All and One
        </span>
        <span className="mt-1 block text-sm text-foreground/80">
          RED-BLUE-Yellow-Ant-Team
        </span>
      </Link>
      <nav className="flex flex-wrap items-center gap-1 text-sm">
        {LINKS.map((link) => (
          <Link
            key={link.href}
            href={link.href}
            className="rounded-full px-3 py-1.5 text-foreground/75 transition hover:bg-white/5 hover:text-foreground"
          >
            {link.label}
          </Link>
        ))}
      </nav>
    </header>
  );
}
