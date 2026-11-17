import React, { useState, useEffect, useRef, useCallback } from "react";
import { flushSync } from "react-dom";
import { invoke, convertFileSrc } from "@tauri-apps/api/core";
import { open, save } from "@tauri-apps/plugin-dialog";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { Crepe } from "@milkdown/crepe";
import { setCodeMirrorTheme } from "@milkdown/crepe/feature/code-mirror";
import { oneDark } from "@codemirror/theme-one-dark";
import {
  CaseSensitive,
  Check,
  CircleAlert,
  Command,
  CornerDownLeft,
  Ellipsis,
  Eye,
  EyeOff,
  FileCode2,
  FileLock2,
  FilePlus2,
  FileText,
  FolderOpen,
  Lock,
  LockKeyhole,
  LockOpen,
  Maximize2,
  Minimize2,
  Palette,
  PanelLeft,
  Plus,
  Printer,
  Save,
  Search,
  ShieldCheck,
  TriangleAlert,
  X,
  Zap,
} from "lucide-react";
import "@milkdown/crepe/theme/common/style.css";
import "@milkdown/crepe/theme/frame.css";
import "./App.css";

interface OpenTab {
  path: string;
  name: string;
  content: string;
  isDirty: boolean;
  isEncrypted: boolean;
  sessionPassword?: string;
}

interface SearchMatch {
  file_path: string;
  line_number: number;
  snippet: string;
}

interface SealReport {
  markdown: string;
  sealed: number;
  rekeyed: number;
  originals_removed: number;
  originals_kept: number;
  skipped: string[];
}

interface OutlineItem {
  level: number;
  text: string;
  // Index into the editor's rendered h1–h4 list, so a click maps to a real node.
  domIndex: number;
}

interface DocStats {
  words: number;
  chars: number;
  lines: number;
  minutes: number;
}

type ThemeName = "cobalt" | "ivory" | "neon" | "nordic";
type Tone = "info" | "success" | "error" | "warn" | "vault";

interface ThemeMeta {
  id: ThemeName;
  label: string;
  dark: boolean;
  swatch: [string, string];
}

const THEMES: ThemeMeta[] = [
  { id: "cobalt", label: "Obsidian Cobalt", dark: true, swatch: ["#05070c", "#1558c9"] },
  { id: "ivory", label: "Editorial Ivory", dark: false, swatch: ["#f9ebd7", "#046a38"] },
  { id: "neon", label: "Cyber Neon", dark: true, swatch: ["#080808", "#d4ff3f"] },
  { id: "nordic", label: "Nordic Slate", dark: true, swatch: ["#1c2028", "#88c0d0"] },
];

const isThemeDark = (id: ThemeName) => THEMES.find((t) => t.id === id)?.dark ?? true;

// The translucent shell is only correct when the native Mica/Acrylic backdrop sits behind it.
const IS_NATIVE = typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

const HEADING_SELECTOR =
    ".ProseMirror h1, .ProseMirror h2, .ProseMirror h3, .ProseMirror h4";
const SIDEBAR_MIN = 200;
const SIDEBAR_MAX = 460;
const SIDEBAR_DEFAULT = 260;
const MAX_SEARCH_ROWS = 200;
const EMPTY_STATS: DocStats = { words: 0, chars: 0, lines: 0, minutes: 0 };
// Idle minutes before decrypted notes are locked again. 0 = never.
const AUTO_LOCK_CHOICES = [1, 5, 15, 30, 0];
const AUTO_LOCK_DEFAULT = 5;
// Once the window is hidden or minimised, decrypted notes lock after this long instead of
// waiting out the full idle time.
const HIDDEN_LOCK_MS = 60_000;
// How often the native window state (minimised / not visible) is read.
const WINDOW_STATE_POLL_MS = 5_000;
type LockReason = "idle" | "panic" | "hidden";

const WELCOME_NOTE =
    "# Welcome to Markseal\n\nA local-first, **zero-knowledge** Markdown editor. Nothing you write leaves this machine.\n\n## Shortcuts\n\n- `Ctrl+K` — command palette\n- `Ctrl+N` — new note\n- `Ctrl+S` — save\n- `Ctrl+L` — encrypt the note with `AES-256-GCM` + `Argon2id`\n- `Ctrl+Shift+F` — search the workspace\n- `Ctrl+E` — export sanitized HTML\n- `Ctrl+P` — print or save as PDF\n- `Ctrl+\\` — focus mode\n\n> Without its passphrase, an encrypted note cannot be recovered.\n";

const baseName = (path: string) => path.split(/[\\/]/).pop() || path;
const isDiskPath = (path: string) => path.includes("/") || path.includes("\\");
const clamp = (n: number, min: number, max: number) => Math.min(max, Math.max(min, n));

const IMAGE_MIME: Record<string, string> = {
  png: "image/png",
  jpg: "image/jpeg",
  jpeg: "image/jpeg",
  gif: "image/gif",
  webp: "image/webp",
  bmp: "image/bmp",
  svg: "image/svg+xml",
  avif: "image/avif",
  ico: "image/x-icon",
};

// "assets/img_1.png.enc" -> "image/png"
function imageMime(url: string): string {
  const inner = url.replace(/\.enc$/i, "").split(".").pop()?.toLowerCase() ?? "";
  return IMAGE_MIME[inner] ?? "application/octet-stream";
}

// A local, unencrypted image reference such as ![x](assets/pic.png).
const PLAINTEXT_IMAGE_REF =
    /!\[[^\]]*\]\((?![a-z][a-z0-9+.-]*:)[^)\s]+\.(?:png|jpe?g|gif|webp|bmp|svg|avif|ico)[)\s]/i;

function readStored(key: string): string | null {
  try {
    return window.localStorage.getItem(key);
  } catch {
    return null;
  }
}

function writeStored(key: string, value: string) {
  try {
    window.localStorage.setItem(key, value);
  } catch {
    // Storage can be unavailable; preferences are a convenience, not state.
  }
}

function initialTheme(): ThemeName {
  const stored = readStored("markseal.theme");
  return THEMES.some((t) => t.id === stored) ? (stored as ThemeName) : "cobalt";
}

function initialSidebarWidth(): number {
  const stored = Number(readStored("markseal.sidebarWidth"));
  return Number.isFinite(stored) && stored > 0
      ? clamp(stored, SIDEBAR_MIN, SIDEBAR_MAX)
      : SIDEBAR_DEFAULT;
}

function initialAutoLock(): number {
  const stored = readStored("markseal.autoLockMinutes");
  const parsed = stored === null ? NaN : Number(stored);
  return AUTO_LOCK_CHOICES.includes(parsed) ? parsed : AUTO_LOCK_DEFAULT;
}

function computeStats(markdown: string): DocStats {
  const text = markdown.replace(/\r/g, "").replace(/\n+$/, "");
  if (!text) return EMPTY_STATS;
  // Drop link/image targets so URLs are not counted as prose.
  const prose = text.replace(/\]\([^)]*\)/g, "]");
  const words = prose.match(/[\p{L}\p{N}]+(?:['’-][\p{L}\p{N}]+)*/gu)?.length ?? 0;
  return {
    words,
    chars: text.length,
    lines: text.split("\n").length,
    minutes: words === 0 ? 0 : Math.max(1, Math.round(words / 230)),
  };
}

const STRENGTH_LABELS = ["", "Weak", "Fair", "Good", "Strong"];

// A rough local estimate (character pool × length). Guidance only, never a gate.
function scorePassphrase(passphrase: string): number {
  if (!passphrase) return 0;
  if (passphrase.length < 8) return 1;
  let pool = 0;
  if (/[a-z]/.test(passphrase)) pool += 26;
  if (/[A-Z]/.test(passphrase)) pool += 26;
  if (/\d/.test(passphrase)) pool += 10;
  if (/[^A-Za-z0-9]/.test(passphrase)) pool += 33;
  const effectiveLength = Math.min(passphrase.length, new Set(passphrase).size * 2);
  const bits = effectiveLength * Math.log2(Math.max(pool, 2));
  if (bits < 45) return 1;
  if (bits < 65) return 2;
  if (bits < 85) return 3;
  return 4;
}

function matchesQuery(haystack: string, query: string): boolean {
  const tokens = query.toLowerCase().split(/\s+/).filter(Boolean);
  const target = haystack.toLowerCase();
  return tokens.every((token) => target.includes(token));
}

function Highlighted({
  text,
  query,
  caseSensitive,
}: {
  text: string;
  query: string;
  caseSensitive: boolean;
}) {
  const needle = query.trim();
  if (!needle) return <>{text}</>;
  const source = caseSensitive ? text : text.toLowerCase();
  const target = caseSensitive ? needle : needle.toLowerCase();
  const parts: React.ReactNode[] = [];
  let cursor = 0;
  let hit = source.indexOf(target);
  while (hit !== -1 && parts.length < 40) {
    if (hit > cursor) parts.push(text.slice(cursor, hit));
    parts.push(<mark key={hit}>{text.slice(hit, hit + target.length)}</mark>);
    cursor = hit + target.length;
    hit = source.indexOf(target, cursor);
  }
  parts.push(text.slice(cursor));
  return <>{parts}</>;
}

interface PaletteCommand {
  id: string;
  group: string;
  label: string;
  keywords?: string;
  shortcut?: string;
  icon: React.ReactNode;
  run: () => void;
}

export default function App() {
  const [workspaceRoot, setWorkspaceRoot] = useState<string>("");
  const [files, setFiles] = useState<string[]>([]);
  const [tabs, setTabs] = useState<OpenTab[]>([
    {
      path: "Untitled-1.md",
      name: "Untitled-1.md",
      content: WELCOME_NOTE,
      isDirty: false,
      isEncrypted: false,
    },
  ]);
  const [activeTabPath, setActiveTabPath] = useState<string>("Untitled-1.md");
  const [theme, setTheme] = useState<ThemeName>(initialTheme);
  const [outline, setOutline] = useState<OutlineItem[]>([]);
  const [activeHeading, setActiveHeading] = useState<number>(-1);
  const [stats, setStats] = useState<DocStats>(EMPTY_STATS);

  // Layout state
  const [zen, setZen] = useState(false);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(
      () => readStored("markseal.sidebarCollapsed") === "1"
  );
  const [sidebarWidth, setSidebarWidth] = useState<number>(initialSidebarWidth);
  const [isResizing, setIsResizing] = useState(false);

  // Search Modal State
  const [isSearchOpen, setIsSearchOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const [caseSensitive, setCaseSensitive] = useState(false);
  const [searchResults, setSearchResults] = useState<SearchMatch[]>([]);
  const [searchSel, setSearchSel] = useState(0);
  const [searchState, setSearchState] = useState<"idle" | "busy" | "done" | "error">("idle");
  const [searchError, setSearchError] = useState("");

  // Command Palette State
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [paletteQuery, setPaletteQuery] = useState("");
  const [paletteSel, setPaletteSel] = useState(0);

  // Vault Encryption / Decryption Modal State
  const [vaultModal, setVaultModal] = useState<{
    mode: "encrypt" | "decrypt" | null;
    targetPath: string;
  }>({ mode: null, targetPath: "" });
  const [vaultPassword, setVaultPassword] = useState("");
  const [vaultConfirm, setVaultConfirm] = useState("");
  const [shredOriginal, setShredOriginal] = useState(true);
  const [showPassphrase, setShowPassphrase] = useState(false);
  const [vaultError, setVaultError] = useState("");
  const [vaultBusy, setVaultBusy] = useState(false);

  const [confirmClosePath, setConfirmClosePath] = useState<string | null>(null);
  const [menuOpen, setMenuOpen] = useState(false);
  // Bumped to rebuild the editor when a tab's content changes underneath it without a path change.
  const [editorEpoch, setEditorEpoch] = useState(0);

  // Vault session protection
  const [autoLockMinutes, setAutoLockMinutes] = useState<number>(initialAutoLock);
  const [captureShield, setCaptureShield] = useState(
      () => readStored("markseal.captureShield") !== "0"
  );
  const [shieldActive, setShieldActive] = useState(false);
  // Covers the whole window the instant a lock starts, before any note is saved or closed.
  const [vaultCurtain, setVaultCurtain] = useState(false);
  // On-screen confirmation for lock actions. The status bar alone is too easy to miss, and it
  // is hidden in focus mode.
  const [lockToast, setLockToast] = useState<{ message: string; tone: Tone; id: number } | null>(null);
  const [justSaved, setJustSaved] = useState(false);
  // `id` re-keys the status line so each new message replays its entrance animation.
  const [status, setStatus] = useState<{ message: string; tone: Tone; id: number }>({
    message: "Ready",
    tone: "info",
    id: 0,
  });

  const editorRef = useRef<HTMLDivElement | null>(null);
  const scrollRef = useRef<HTMLDivElement | null>(null);
  const tabBarRef = useRef<HTMLDivElement | null>(null);
  const crepeRef = useRef<Crepe | null>(null);
  // The tab the live editor instance belongs to; content is only ever committed to this path.
  const crepePathRef = useRef<string | null>(null);
  // Markdown of the active tab as last saved/loaded. null = unknown, treat any edit as dirty.
  const baselineRef = useRef<string | null>(null);
  const untitledCounter = useRef(1);
  const searchSeq = useRef(0);
  const spyFrame = useRef(0);
  const spyLockUntil = useRef(0);
  const savedTimer = useRef(0);
  const lastActivityRef = useRef(Date.now());
  const lockingRef = useRef(false);
  const lockVaultRef = useRef<(reason: LockReason) => Promise<void>>(async () => {});
  const tabsRef = useRef(tabs);
  tabsRef.current = tabs;
  const activeTabPathRef = useRef(activeTabPath);
  activeTabPathRef.current = activeTabPath;
  const themeRef = useRef(theme);
  themeRef.current = theme;

  const activeTab = tabs.find((t) => t.path === activeTabPath) || tabs[0];
  const anyModalOpen =
      paletteOpen || isSearchOpen || vaultModal.mode !== null || confirmClosePath !== null;

  const notify = useCallback((message: string, tone: Tone = "info") => {
    setStatus((prev) => ({ message, tone, id: prev.id + 1 }));
  }, []);

  // Theme switch with a circular reveal from the point that was clicked. Falls back to an
  // instant swap when the View Transitions API is missing or the user prefers reduced motion.
  const switchTheme = (next: ThemeName, origin?: { x: number; y: number }) => {
    if (next === theme) return;
    const doc = document as Document & {
      startViewTransition?: (update: () => void) => unknown;
    };
    const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (!doc.startViewTransition || reduceMotion) {
      setTheme(next);
      return;
    }
    const root = document.documentElement;
    root.style.setProperty("--vt-x", `${origin?.x ?? window.innerWidth / 2}px`);
    root.style.setProperty("--vt-y", `${origin?.y ?? 0}px`);
    doc.startViewTransition(() => {
      flushSync(() => setTheme(next));
    });
  };

  const flashSaved = () => {
    setJustSaved(true);
    window.clearTimeout(savedTimer.current);
    savedTimer.current = window.setTimeout(() => setJustSaved(false), 1400);
  };

  const focusEditor = () => {
    window.setTimeout(() => {
      editorRef.current?.querySelector<HTMLElement>(".ProseMirror")?.focus();
    }, 0);
  };

  // Outline + stats are derived from the live editor: headings come from the rendered DOM so
  // the list always matches what a click can scroll to (code-block "#" lines never leak in).
  const refreshDerived = useCallback((markdown: string) => {
    setStats(computeStats(markdown));
    const root = editorRef.current;
    const headings = root
        ? Array.from(root.querySelectorAll<HTMLElement>(HEADING_SELECTOR))
        : [];
    setOutline(
        headings
            .map((el, domIndex) => ({
              level: Number(el.tagName.charAt(1)),
              text: (el.textContent || "").trim(),
              domIndex,
            }))
            .filter((h) => h.text.length > 0)
    );
  }, []);

  // Initialize / Rebuild Milkdown Crepe on active tab switch
  useEffect(() => {
    if (!editorRef.current || !activeTab) return;

    const host = editorRef.current;
    const tabPath = activeTab.path;
    let destroyed = false;
    let userTouched = false;
    let refreshTimer = 0;
    host.innerHTML = "";
    baselineRef.current = activeTab.isDirty ? null : activeTab.content;

    // Decrypted images live only in memory as blob: URLs, released with the editor.
    const blobUrls: string[] = [];
    const decryptedImages = new Map<string, Promise<string>>();
    // The tab as it is right now — the passphrase can change (re-key) while the editor lives.
    const liveTab = () => tabsRef.current.find((t) => t.path === tabPath);

    const upload = async (file: File): Promise<string> => {
      const mdPath = activeTab?.path;
      if (mdPath && (mdPath.includes("/") || mdPath.includes("\\"))) {
        const bytes = Array.from(new Uint8Array(await file.arrayBuffer()));
        const ext = file.name.includes(".") ? file.name.split(".").pop() || "png" : "png";
        const tab = liveTab();
        if (tab?.isEncrypted) {
          // An image in an encrypted note must never reach the disk in the clear.
          if (!tab.sessionPassword) {
            throw new Error("Unlock the note before adding images to it.");
          }
          return await invoke<string>("save_encrypted_image", {
            activeMdPath: mdPath,
            imageBytes: bytes,
            extension: ext,
            password: tab.sessionPassword,
          });
        }
        return await invoke<string>("save_pasted_image", {
          activeMdPath: mdPath,
          imageBytes: bytes,
          extension: ext,
        });
      }
      return URL.createObjectURL(file);
    };

    // Editor plugins normalise the document right after load; only edits that follow real
    // user input may flip the tab to dirty.
    const markTouched = () => {
      userTouched = true;
    };
    const touchEvents = ["keydown", "beforeinput", "paste", "cut", "drop", "pointerdown"];
    touchEvents.forEach((type) => host.addEventListener(type, markTouched, true));

    let mermaidIdCounter = 0;
    const crepe = new Crepe({
      root: host,
      defaultValue: activeTab.content,
      features: {
        [Crepe.Feature.CodeMirror]: true,
        [Crepe.Feature.Latex]: true,
      },
      featureConfigs: {
        [Crepe.Feature.CodeMirror]: {
          theme: isThemeDark(themeRef.current) ? oneDark : [],
          renderPreview: (language, content, applyPreview) => {
            if (language.toLowerCase() !== "mermaid") return null;

            const loading = document.createElement("div");
            loading.className = "mermaid-preview-loading";
            loading.textContent = "Rendering diagram…";
            const id = `markseal-mermaid-${++mermaidIdCounter}`;
            const dark = isThemeDark(themeRef.current);

            void import("mermaid")
              .then(({ default: mermaid }) => {
                mermaid.initialize({
                  startOnLoad: false,
                  securityLevel: "strict",
                  theme: dark ? "dark" : "default",
                });
                return mermaid.render(id, content);
              })
              .then(({ svg }) => applyPreview(svg))
              .catch((error: unknown) => {
                const failure = document.createElement("div");
                failure.className = "mermaid-error";
                failure.textContent = `Unable to render Mermaid diagram: ${String(error)}`;
                applyPreview(failure);
              });

            return loading;
          },
        },
        [Crepe.Feature.ImageBlock]: {
          onUpload: upload,
          blockOnUpload: upload,
          inlineOnUpload: upload,
          proxyDomURL: (url: string) => {
            const mdPath = activeTab?.path;
            if (!mdPath || /^(https?:|data:|blob:|asset:|http:\/\/asset\.localhost)/i.test(url)) return url;
            const sep = mdPath.includes("\\") ? "\\" : "/";
            const dir = mdPath.includes(sep) ? mdPath.slice(0, mdPath.lastIndexOf(sep)) : "";
            if (!dir) return url;
            const abs = `${dir}${sep}${url.replace(/^\.?[\\/]/, "").replace(/[\\/]/g, sep)}`;
            if (!/\.enc$/i.test(url)) return convertFileSrc(abs);

            // Encrypted image: decrypt in memory and show it from a blob: URL.
            const cached = decryptedImages.get(url);
            if (cached) return cached;
            const password = liveTab()?.sessionPassword;
            if (!password) return url;
            const pending = invoke<ArrayBuffer | number[]>("read_encrypted_image", {
              filePath: abs,
              password,
            })
                .then((data) => {
                  const bytes = data instanceof ArrayBuffer ? data : new Uint8Array(data);
                  const blobUrl = URL.createObjectURL(new Blob([bytes], { type: imageMime(url) }));
                  if (destroyed) URL.revokeObjectURL(blobUrl);
                  else blobUrls.push(blobUrl);
                  return blobUrl;
                })
                .catch((err: unknown) => {
                  decryptedImages.delete(url);
                  notify(`Could not decrypt image ${baseName(url)}: ${err}`, "error");
                  return url;
                });
            decryptedImages.set(url, pending);
            return pending;
          },
        },
      },
    });

    crepe.on((listener) => {
      listener.markdownUpdated((_ctx, markdown) => {
        if (destroyed) return;
        if (!userTouched) {
          if (baselineRef.current !== null) baselineRef.current = markdown;
        } else {
          const dirty = baselineRef.current === null || markdown !== baselineRef.current;
          setTabs((prev) =>
              prev.some((t) => t.path === tabPath && t.isDirty !== dirty)
                  ? prev.map((t) => (t.path === tabPath ? { ...t, isDirty: dirty } : t))
                  : prev
          );
        }
        window.clearTimeout(refreshTimer);
        refreshTimer = window.setTimeout(() => {
          if (!destroyed) refreshDerived(markdown);
        }, 80);
      });
    });

    crepe.create().then(() => {
      if (destroyed) {
        crepe.destroy();
        return;
      }
      crepeRef.current = crepe;
      crepePathRef.current = tabPath;
      refreshDerived(activeTab.content);
      setActiveHeading(-1);
      if (scrollRef.current) scrollRef.current.scrollTop = 0;
    });

    return () => {
      destroyed = true;
      window.clearTimeout(refreshTimer);
      touchEvents.forEach((type) => host.removeEventListener(type, markTouched, true));
      blobUrls.forEach((blobUrl) => URL.revokeObjectURL(blobUrl));
      if (crepeRef.current === crepe) {
        crepe.destroy();
        crepeRef.current = null;
        crepePathRef.current = null;
      }
    };
  }, [activeTabPath, editorEpoch]);

  // Live theme switch: CSS variables repaint the editor; only CodeMirror's syntax palette
  // needs an explicit swap. The Milkdown instance is never recreated.
  useEffect(() => {
    writeStored("markseal.theme", theme);
    try {
      crepeRef.current?.editor.action(setCodeMirrorTheme(isThemeDark(theme) ? oneDark : []));
    } catch {
      // Editor is mid-rebuild; the next instance reads the theme at creation.
    }
  }, [theme]);

  useEffect(() => {
    writeStored("markseal.sidebarCollapsed", sidebarCollapsed ? "1" : "0");
  }, [sidebarCollapsed]);

  useEffect(() => {
    if (!isResizing) writeStored("markseal.sidebarWidth", String(sidebarWidth));
  }, [sidebarWidth, isResizing]);

  useEffect(() => {
    tabBarRef.current
        ?.querySelector(".tab.active")
        ?.scrollIntoView({ block: "nearest", inline: "nearest" });
  }, [activeTabPath, tabs.length]);

  const readEditorMarkdown = (): string => {
    if (!crepeRef.current) return activeTab?.content || "";
    try {
      return crepeRef.current.getMarkdown();
    } catch {
      return activeTab?.content || "";
    }
  };

  // Copy the live editor's markdown into its tab. Must run before anything swaps the editor.
  const commitActiveContent = () => {
    const path = crepePathRef.current;
    if (!path || !crepeRef.current) return;
    let markdown: string;
    try {
      markdown = crepeRef.current.getMarkdown();
    } catch {
      return;
    }
    setTabs((prev) =>
        prev.map((t) => (t.path === path && t.content !== markdown ? { ...t, content: markdown } : t))
    );
  };

  const activateTab = (path: string) => {
    if (path === activeTabPath) return;
    commitActiveContent();
    setActiveTabPath(path);
  };

  const syncCurrentEditorContent = (): string => {
    const md = readEditorMarkdown();
    refreshDerived(md);
    return md;
  };

  const refreshWorkspace = async (rootPath: string) => {
    try {
      const list = await invoke<string[]>("list_markdown_files", {
        dirPath: rootPath,
      });
      setFiles(list);
    } catch (err) {
      notify(`Workspace error: ${err}`, "error");
    }
  };

  const handleOpenFolder = async () => {
    try {
      const selected = await open({ directory: true, multiple: false });
      if (typeof selected === "string") {
        setWorkspaceRoot(selected);
        try {
          await invoke("set_workspace_root", { dirPath: selected });
        } catch (e) {
          console.warn("set_workspace_root notice:", e);
        }
        await refreshWorkspace(selected);
        notify(`Opened workspace: ${selected}`, "success");
      }
    } catch (err) {
      notify(`Could not open folder: ${err}`, "error");
    }
  };

  // Handler to create a brand new note
  const handleNewNote = () => {
    const timestamp = Date.now();
    const newName = `note_${timestamp}.md`;
    const sep = workspaceRoot.includes("/") && !workspaceRoot.includes("\\") ? "/" : "\\";
    const newPath = workspaceRoot ? `${workspaceRoot}${sep}${newName}` : newName;
    const initialContent = "# Untitled Note\n\nStart writing here...";

    const newTab: OpenTab = {
      path: newPath,
      name: newName,
      content: initialContent,
      isDirty: false,
      isEncrypted: false,
    };

    commitActiveContent();
    setTabs((prev) => [...prev, newTab]);
    setActiveTabPath(newPath);
    notify(`Created new note: ${newName}`, "success");
  };

  const openVault = (mode: "encrypt" | "decrypt", targetPath: string) => {
    setVaultPassword("");
    setVaultConfirm("");
    setVaultError("");
    setShowPassphrase(false);
    setVaultBusy(false);
    setVaultModal({ mode, targetPath });
  };

  const closeVault = () => {
    setVaultPassword("");
    setVaultConfirm("");
    setVaultError("");
    setShowPassphrase(false);
    setVaultBusy(false);
    setVaultModal({ mode: null, targetPath: "" });
  };

  const handleOpenFile = async (filePath: string) => {
    const existing = tabs.find((t) => t.path === filePath);
    if (existing) {
      activateTab(filePath);
      return;
    }

    try {
      const encrypted = await invoke<boolean>("is_encrypted_note", { filePath });
      if (encrypted) {
        openVault("decrypt", filePath);
        return;
      }

      const content = await invoke<string>("read_markdown_file", { filePath });
      const name = baseName(filePath);
      commitActiveContent();
      setTabs((prev) =>
          prev.some((t) => t.path === filePath)
              ? prev
              : [...prev, { path: filePath, name, content, isDirty: false, isEncrypted: false }]
      );
      setActiveTabPath(filePath);
      notify(`Loaded ${name}`, "success");
    } catch (err) {
      notify(`Read error: ${err}`, "error");
    }
  };

  const handleSaveCurrentTab = async () => {
    if (!activeTab) return;
    const latestMarkdown = syncCurrentEditorContent();

    let targetPath = activeTab.path;
    if (
        !targetPath.includes("/") &&
        !targetPath.includes("\\")
    ) {
      const chosen = await save({
        defaultPath: activeTab.name,
        filters: [
          { name: "Markdown", extensions: ["md", "markdown", "enc"] },
        ],
      });
      if (!chosen) return;
      targetPath = chosen;
      try {
        await invoke("authorize_dialog_path", { path: chosen });
      } catch (err) {
        console.warn("authorize_dialog_path error:", err);
      }
    }

    try {
      if (activeTab.isEncrypted) {
        if (!activeTab.sessionPassword) {
          openVault("encrypt", targetPath);
          return;
        }
        await invoke("save_encrypted_markdown", {
          filePath: targetPath,
          content: latestMarkdown,
          password: activeTab.sessionPassword,
        });
      } else {
        await invoke("save_markdown_file", {
          filePath: targetPath,
          content: latestMarkdown,
        });
      }

      const newName = baseName(targetPath);
      baselineRef.current = latestMarkdown;
      setTabs((prev) =>
          prev.map((t) =>
              t.path === activeTab.path
                  ? {
                    ...t,
                    path: targetPath,
                    name: newName,
                    content: latestMarkdown,
                    isDirty: false,
                  }
                  : t
          )
      );
      setActiveTabPath(targetPath);
      if (workspaceRoot) await refreshWorkspace(workspaceRoot);
      flashSaved();
      if (activeTab.isEncrypted) {
        notify(`Saved encrypted vault: ${newName}`, "vault");
      } else {
        notify(`Saved: ${newName}`, "success");
      }
    } catch (err) {
      notify(`Save error: ${err}`, "error");
    }
  };

  // Vault Encryption / Decryption Handlers
  const handleConfirmVaultAction = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!vaultModal.mode || vaultBusy) return;
    setVaultError("");

    if (vaultModal.mode === "decrypt") {
      setVaultBusy(true);
      try {
        const plaintext = await invoke<string>("read_encrypted_markdown", {
          filePath: vaultModal.targetPath,
          password: vaultPassword,
        });
        const name = baseName(vaultModal.targetPath);
        const targetPath = vaultModal.targetPath;
        const sessionPassword = vaultPassword;
        commitActiveContent();
        setTabs((prev) =>
            prev.some((t) => t.path === targetPath)
                ? prev
                : [
                  ...prev,
                  {
                    path: targetPath,
                    name,
                    content: plaintext,
                    isDirty: false,
                    isEncrypted: true,
                    sessionPassword,
                  },
                ]
        );
        setActiveTabPath(targetPath);
        closeVault();
        notify(`Decrypted vault note: ${name}`, "vault");
      } catch (err) {
        setVaultBusy(false);
        setVaultError(String(err));
        notify(`${err}`, "error");
      }
    } else if (vaultModal.mode === "encrypt") {
      if (vaultPassword.length < 8) {
        setVaultError("Passphrase must be at least 8 characters.");
        return;
      }
      if (vaultPassword !== vaultConfirm) {
        setVaultError("Passphrases do not match.");
        return;
      }

      const latestMarkdown = syncCurrentEditorContent();
      let encPath = vaultModal.targetPath;
      if (!encPath.includes("/") && !encPath.includes("\\")) {
        const chosen = await save({
          defaultPath: `${activeTab.name.replace(/\.md$/i, "")}.md.enc`,
          filters: [{ name: "Markseal Encrypted Vault", extensions: ["enc"] }],
        });
        if (!chosen) return;
        encPath = chosen;
        try {
          await invoke("authorize_dialog_path", { path: chosen });
        } catch (err) {
          console.warn("authorize_dialog_path error:", err);
        }
      } else if (!encPath.toLowerCase().endsWith(".enc")) {
        encPath = `${encPath}.enc`;
      }

      setVaultBusy(true);
      try {
        // One all-or-nothing step: the note and every image it references end up under the
        // same passphrase, or nothing changes.
        const report = await invoke<SealReport>("seal_note", {
          filePath: encPath,
          content: latestMarkdown,
          password: vaultPassword,
          previousPassword: activeTab.isEncrypted ? activeTab.sessionPassword ?? null : null,
          removePlaintextAssets: shredOriginal && isDiskPath(activeTab.path),
        });
        const sealedMarkdown = report.markdown;

        if (
            shredOriginal &&
            activeTab.path !== encPath &&
            (activeTab.path.includes("/") || activeTab.path.includes("\\"))
        ) {
          await invoke("delete_note_file", { filePath: activeTab.path });
        }

        const newName = baseName(encPath);
        const sessionPassword = vaultPassword;
        baselineRef.current = sealedMarkdown;
        setTabs((prev) =>
            prev.map((t) =>
                t.path === activeTab.path
                    ? {
                      path: encPath,
                      name: newName,
                      content: sealedMarkdown,
                      isDirty: false,
                      isEncrypted: true,
                      sessionPassword,
                    }
                    : t
            )
        );
        setActiveTabPath(encPath);
        // Same path but rewritten image links: the live editor must reload them.
        if (activeTab.path === encPath && sealedMarkdown !== latestMarkdown) {
          setEditorEpoch((n) => n + 1);
        }
        closeVault();
        if (workspaceRoot) await refreshWorkspace(workspaceRoot);

        const imageCount = report.sealed + report.rekeyed;
        const imageNote =
            imageCount > 0 ? ` · ${imageCount} image${imageCount === 1 ? "" : "s"} encrypted` : "";
        if (report.originals_kept > 0) {
          notify(
              `Encrypted ${newName}${imageNote}, but ${report.originals_kept} unencrypted image file(s) could not be removed — delete them from the assets folder.`,
              "warn"
          );
        } else if (report.skipped.length > 0) {
          notify(
              `Encrypted ${newName}${imageNote}. Left unencrypted: ${report.skipped.join("; ")}`,
              "warn"
          );
        } else {
          notify(`Encrypted with AES-256-GCM + Argon2id: ${newName}${imageNote}`, "vault");
        }
      } catch (err) {
        setVaultBusy(false);
        setVaultError(`Encryption error: ${err}`);
        notify(`Encryption error: ${err}`, "error");
      }
    }
  };

  const closeTabNow = (pathToClose: string) => {
    const index = tabs.findIndex((t) => t.path === pathToClose);
    if (index === -1) return;
    const remaining = tabs.filter((t) => t.path !== pathToClose);
    if (remaining.length === 0) {
      untitledCounter.current += 1;
      const name = `Untitled-${untitledCounter.current}.md`;
      const fallback: OpenTab = {
        path: name,
        name,
        content: "# New Note\n",
        isDirty: false,
        isEncrypted: false,
      };
      setTabs([fallback]);
      setActiveTabPath(fallback.path);
    } else {
      setTabs(remaining);
      if (activeTabPath === pathToClose) {
        setActiveTabPath(remaining[Math.min(index, remaining.length - 1)].path);
      }
    }
  };

  // Locks every decrypted note: the screen is covered first, unsaved edits are written back
  // encrypted, then the plaintext and passphrases are dropped from app state. "panic" (the
  // manual shortcut) also clears the clipboard. A note that cannot be saved stays open —
  // locking must never lose work.
  const announceLock = (message: string, tone: Tone) => {
    notify(message, tone);
    setLockToast((prev) => ({ message, tone, id: (prev?.id ?? 0) + 1 }));
  };

  // Resolves true only if the clipboard was really emptied. Capped, so a clipboard that never
  // answers cannot hold up a lock.
  const clearClipboard = async (): Promise<boolean> => {
    try {
      return await Promise.race([
        navigator.clipboard.writeText("").then(() => true),
        new Promise<boolean>((resolve) => window.setTimeout(() => resolve(false), 800)),
      ]);
    } catch {
      return false;
    }
  };

  const lockVault = async (reason: LockReason) => {
    if (lockingRef.current) return;
    const secretTabs = tabsRef.current.filter((t) => t.isEncrypted);
    if (secretTabs.length === 0) {
      if (reason === "panic") announceLock("Nothing to lock — no encrypted note is open.", "info");
      return;
    }
    lockingRef.current = true;
    const startedAt = performance.now();
    setVaultCurtain(true);
    try {
      closeVault();
      setPaletteOpen(false);
      setIsSearchOpen(false);
      setConfirmClosePath(null);
      setMenuOpen(false);

      const clipboardCleared = reason === "panic" ? await clearClipboard() : false;

      const livePath = crepePathRef.current;
      let liveMarkdown: string | null = null;
      if (livePath && crepeRef.current) {
        try {
          liveMarkdown = crepeRef.current.getMarkdown();
        } catch {
          liveMarkdown = null;
        }
      }

      const kept = new Set<string>();
      let saved = 0;
      for (const tab of secretTabs) {
        const isLive = tab.path === livePath && liveMarkdown !== null;
        const content = isLive ? (liveMarkdown as string) : tab.content;
        const dirty =
            tab.isDirty ||
            (isLive && baselineRef.current !== null && content !== baselineRef.current);
        if (!dirty) continue;
        if (!tab.sessionPassword) {
          kept.add(tab.path);
          continue;
        }
        try {
          await invoke("save_encrypted_markdown", {
            filePath: tab.path,
            content,
            password: tab.sessionPassword,
          });
          saved += 1;
        } catch {
          kept.add(tab.path);
        }
      }

      const locked = new Set(secretTabs.filter((t) => !kept.has(t.path)).map((t) => t.path));
      const remaining = tabsRef.current.filter((t) => !locked.has(t.path));
      if (remaining.length === 0) {
        untitledCounter.current += 1;
        const name = `Untitled-${untitledCounter.current}.md`;
        setTabs([{ path: name, name, content: "# New Note\n", isDirty: false, isEncrypted: false }]);
        setActiveTabPath(name);
      } else {
        setTabs(remaining);
        if (locked.has(activeTabPathRef.current)) {
          setActiveTabPath(remaining[remaining.length - 1].path);
        }
      }

      // A manual lock holds the cover for a moment, so it is obvious that it happened.
      if (reason === "panic") {
        const shown = performance.now() - startedAt;
        if (shown < 450) await new Promise((resolve) => window.setTimeout(resolve, 450 - shown));
      }

      const count = locked.size;
      const notes = `${count} note${count === 1 ? "" : "s"}`;
      const savedNote = saved > 0 ? ` · ${saved} saved first` : "";
      if (kept.size > 0) {
        announceLock(
            `Locked ${notes}, but ${kept.size} could not be saved and stay${kept.size === 1 ? "s" : ""} open.`,
            "error"
        );
      } else if (reason === "idle") {
        announceLock(`Auto-locked ${notes} after ${autoLockMinutes} min idle${savedNote}`, "vault");
      } else if (reason === "hidden") {
        announceLock(`Auto-locked ${notes} while the window was out of view${savedNote}`, "vault");
      } else {
        announceLock(
            clipboardCleared
                ? `Locked ${notes} and cleared the clipboard${savedNote}`
                : `Locked ${notes}${savedNote} · clipboard could not be cleared`,
            "vault"
        );
      }
    } catch (err) {
      // Never leave the cover up or the lock stuck "in progress" after an unexpected error.
      announceLock(`Lock did not finish: ${String(err)}`, "error");
    } finally {
      setVaultCurtain(false);
      lockingRef.current = false;
    }
  };
  lockVaultRef.current = lockVault;

  useEffect(() => {
    if (!lockToast) return;
    const timer = window.setTimeout(() => setLockToast(null), 3200);
    return () => window.clearTimeout(timer);
  }, [lockToast]);

  // Any key, click, scroll or mouse movement counts as activity.
  useEffect(() => {
    const bump = () => {
      lastActivityRef.current = Date.now();
    };
    const events = ["keydown", "pointerdown", "pointermove", "wheel"];
    events.forEach((type) => window.addEventListener(type, bump, { capture: true, passive: true }));
    return () => events.forEach((type) => window.removeEventListener(type, bump, true));
  }, []);

  // Idle check runs off wall-clock time, so it still fires correctly after the window was
  // hidden, minimised or the machine slept.
  useEffect(() => {
    writeStored("markseal.autoLockMinutes", String(autoLockMinutes));
    if (autoLockMinutes === 0) return;
    const limit = autoLockMinutes * 60_000;
    const timer = window.setInterval(() => {
      if (Date.now() - lastActivityRef.current >= limit) void lockVaultRef.current("idle");
    }, 10_000);
    return () => window.clearInterval(timer);
  }, [autoLockMinutes]);

  // Out of sight: lock shortly after the window is hidden or minimised. Two signals are used,
  // because on Windows the webview does not report a minimised window as hidden: the page's
  // own visibility state, and the native window state read through Tauri. The elapsed time is
  // also checked on the wall clock when the window comes back, because timers in a hidden
  // window can be delayed and stop altogether while the machine sleeps.
  useEffect(() => {
    if (autoLockMinutes === 0) return;
    const grace = Math.min(HIDDEN_LOCK_MS, autoLockMinutes * 60_000);
    const appWindow = getCurrentWindow();
    let disposed = false;
    let pageHidden = document.visibilityState === "hidden";
    let windowHidden = false;
    let hiddenAt: number | null = pageHidden ? Date.now() : null;
    let fired = false;
    let timer = 0;
    const lockOnce = () => {
      if (fired) return;
      fired = true;
      void lockVaultRef.current("hidden");
    };
    const evaluate = () => {
      if (pageHidden || windowHidden) {
        if (hiddenAt === null) {
          hiddenAt = Date.now();
          fired = false;
          window.clearTimeout(timer);
          timer = window.setTimeout(lockOnce, grace);
        } else if (Date.now() - hiddenAt >= grace) {
          lockOnce();
        }
        return;
      }
      window.clearTimeout(timer);
      if (hiddenAt !== null && Date.now() - hiddenAt >= grace) lockOnce();
      hiddenAt = null;
      fired = false;
    };
    const onVisibility = () => {
      pageHidden = document.visibilityState === "hidden";
      evaluate();
    };
    const pollWindow = async () => {
      try {
        const [minimised, visible] = await Promise.all([
          appWindow.isMinimized(),
          appWindow.isVisible(),
        ]);
        if (disposed) return;
        windowHidden = minimised || !visible;
      } catch {
        // Not running inside Tauri, or the call failed: keep the last known window state.
        return;
      }
      evaluate();
    };
    document.addEventListener("visibilitychange", onVisibility);
    const poll = window.setInterval(() => void pollWindow(), WINDOW_STATE_POLL_MS);
    void pollWindow();
    return () => {
      disposed = true;
      window.clearTimeout(timer);
      window.clearInterval(poll);
      document.removeEventListener("visibilitychange", onVisibility);
    };
  }, [autoLockMinutes]);

  // Screen-capture shield: while a decrypted note (or the passphrase dialog) is on screen, the
  // window is excluded from screenshots, screen sharing and Windows Recall.
  const hasDecryptedNote = tabs.some((t) => t.isEncrypted);
  const wantShield = captureShield && (hasDecryptedNote || vaultModal.mode !== null);
  useEffect(() => {
    writeStored("markseal.captureShield", captureShield ? "1" : "0");
  }, [captureShield]);
  useEffect(() => {
    if (!IS_NATIVE) return;
    let cancelled = false;
    getCurrentWindow()
        .setContentProtected(wantShield)
        .then(() => {
          if (!cancelled) setShieldActive(wantShield);
        })
        .catch((err: unknown) => {
          console.warn("setContentProtected failed:", err);
          if (!cancelled) setShieldActive(false);
        });
    return () => {
      cancelled = true;
    };
  }, [wantShield]);

  const handleCloseTab = (pathToClose: string, e?: React.MouseEvent) => {
    e?.stopPropagation();
    const tab = tabs.find((t) => t.path === pathToClose);
    if (!tab) return;
    if (tab.isDirty) {
      setConfirmClosePath(pathToClose);
      return;
    }
    closeTabNow(pathToClose);
  };

  const handleExportHtml = async () => {
    if (!activeTab) return;
    const latestMarkdown = syncCurrentEditorContent();
    const defaultHtmlName = `${activeTab.name.replace(/(\.md)?(\.enc)?$/i, "")}.html`;

    try {
      const targetPath = await save({
        defaultPath: defaultHtmlName,
        filters: [{ name: "HTML Document", extensions: ["html"] }],
      });
      if (!targetPath) return;
      try {
        await invoke("authorize_dialog_path", { path: targetPath });
      } catch (err) {
        console.warn("authorize_dialog_path error:", err);
      }

      await invoke("export_to_html", {
        targetPath,
        markdownContent: latestMarkdown,
        title: activeTab.name.replace(/(\.md)?(\.enc)?$/i, ""),
        theme,
      });
      notify(`Exported sanitized HTML: ${targetPath}`, "success");
    } catch (err) {
      notify(`HTML export error: ${err}`, "error");
    }
  };

  const handlePrintPdf = () => {
    window.print();
  };

  const openSearch = () => {
    setSearchSel(0);
    setIsSearchOpen(true);
  };

  const closeSearch = () => {
    setIsSearchOpen(false);
    focusEditor();
  };

  const openPalette = () => {
    setPaletteQuery("");
    setPaletteSel(0);
    setPaletteOpen(true);
  };

  const closePalette = () => {
    setPaletteOpen(false);
    focusEditor();
  };

  const runMenu = (action: () => void) => {
    setMenuOpen(false);
    action();
  };

  // The overflow menu closes on any click outside it.
  useEffect(() => {
    if (!menuOpen) return;
    const onPointerDown = (e: PointerEvent) => {
      if (!(e.target as HTMLElement).closest(".menu-anchor")) setMenuOpen(false);
    };
    window.addEventListener("pointerdown", onPointerDown, true);
    return () => window.removeEventListener("pointerdown", onPointerDown, true);
  }, [menuOpen]);

  const requestEncrypt = () => {
    if (!activeTab) return;
    openVault("encrypt", activeTab.path);
  };

  // Workspace search runs as you type (debounced); stale responses are dropped by sequence id.
  useEffect(() => {
    if (!isSearchOpen) return;
    const seq = ++searchSeq.current;
    if (!workspaceRoot || searchQuery.trim().length < 2) {
      setSearchResults([]);
      setSearchState("idle");
      return;
    }
    setSearchState("busy");
    const timer = window.setTimeout(async () => {
      try {
        const matches = await invoke<SearchMatch[]>("search_workspace", {
          workspaceRoot,
          query: searchQuery,
          caseSensitive,
        });
        if (seq !== searchSeq.current) return;
        setSearchResults(matches);
        setSearchSel(0);
        setSearchState("done");
      } catch (err) {
        if (seq !== searchSeq.current) return;
        setSearchResults([]);
        setSearchError(String(err));
        setSearchState("error");
      }
    }, 220);
    return () => window.clearTimeout(timer);
  }, [isSearchOpen, searchQuery, caseSensitive, workspaceRoot]);

  const visibleResults = searchResults.slice(0, MAX_SEARCH_ROWS);

  const openSearchResult = (match: SearchMatch) => {
    setIsSearchOpen(false);
    void handleOpenFile(match.file_path);
  };

  const onSearchKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setSearchSel((i) => Math.min(i + 1, visibleResults.length - 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setSearchSel((i) => Math.max(i - 1, 0));
    } else if (e.key === "Enter") {
      e.preventDefault();
      const match = visibleResults[searchSel];
      if (match) openSearchResult(match);
    }
  };

  // ---- Command palette ----------------------------------------------------
  const paletteCommands: PaletteCommand[] = paletteOpen
      ? [
        { id: "new", group: "Actions", label: "New note", shortcut: "Ctrl+N", icon: <FilePlus2 size={16} />, run: handleNewNote },
        { id: "open", group: "Actions", label: "Open folder…", keywords: "workspace directory", icon: <FolderOpen size={16} />, run: () => void handleOpenFolder() },
        { id: "save", group: "Actions", label: "Save note", shortcut: "Ctrl+S", icon: <Save size={16} />, run: () => void handleSaveCurrentTab() },
        {
          id: "encrypt",
          group: "Actions",
          label: activeTab?.isEncrypted ? "Re-key vault (change passphrase)" : "Lock / encrypt note",
          keywords: "vault aes argon2 passphrase password zero-knowledge",
          shortcut: "Ctrl+L",
          icon: <Lock size={16} />,
          run: requestEncrypt,
        },
        { id: "search", group: "Actions", label: "Search workspace", keywords: "find grep", shortcut: "Ctrl+Shift+F", icon: <Search size={16} />, run: openSearch },
        { id: "export", group: "Actions", label: "Export HTML", keywords: "sanitized standalone", shortcut: "Ctrl+E", icon: <FileCode2 size={16} />, run: () => void handleExportHtml() },
        { id: "print", group: "Actions", label: "Print / save as PDF", shortcut: "Ctrl+P", icon: <Printer size={16} />, run: handlePrintPdf },
        { id: "close", group: "Actions", label: "Close tab", shortcut: "Ctrl+W", icon: <X size={16} />, run: () => handleCloseTab(activeTabPath) },
        { id: "zen", group: "View", label: zen ? "Exit focus mode" : "Enter focus mode", keywords: "zen distraction free", shortcut: "Ctrl+\\", icon: zen ? <Minimize2 size={16} /> : <Maximize2 size={16} />, run: () => setZen((z) => !z) },
        { id: "sidebar", group: "View", label: sidebarCollapsed ? "Show sidebar" : "Hide sidebar", keywords: "explorer outline panel", shortcut: "Ctrl+Shift+E", icon: <PanelLeft size={16} />, run: () => setSidebarCollapsed((c) => !c) },
        { id: "lock-now", group: "Security", label: "Lock all notes and clear clipboard", keywords: "panic vault close hide boss", shortcut: "Ctrl+Shift+L", icon: <LockKeyhole size={16} />, run: () => void lockVault("panic") },
        ...AUTO_LOCK_CHOICES.map<PaletteCommand>((minutes) => ({
          id: `autolock-${minutes}`,
          group: "Security",
          label:
              (minutes === 0 ? "Auto-lock: never" : `Auto-lock: after ${minutes} minute${minutes === 1 ? "" : "s"} idle`) +
              (minutes === autoLockMinutes ? " (current)" : ""),
          keywords: "idle timeout timer vault",
          icon: <Lock size={16} />,
          run: () => {
            setAutoLockMinutes(minutes);
            notify(minutes === 0 ? "Auto-lock is off." : `Decrypted notes lock after ${minutes} min idle.`);
          },
        })),
        {
          id: "shield",
          group: "Security",
          label: captureShield ? "Screen-capture shield: turn off" : "Screen-capture shield: turn on",
          keywords: "screenshot recall screen share recording privacy",
          icon: <EyeOff size={16} />,
          run: () => {
            setCaptureShield((on) => !on);
            notify(
                captureShield
                    ? "Screen-capture shield is off — decrypted notes can be screenshotted."
                    : "Screen-capture shield is on while a decrypted note is open."
            );
          },
        },
        ...THEMES.map<PaletteCommand>((t) => ({
          id: `theme-${t.id}`,
          group: "Theme",
          label: `Theme: ${t.label}${t.id === theme ? " (current)" : ""}`,
          keywords: `color colour appearance ${t.dark ? "dark" : "light"}`,
          icon: <Palette size={16} />,
          run: () => switchTheme(t.id),
        })),
        ...(paletteQuery.trim()
            ? files.map<PaletteCommand>((f) => ({
              id: `file-${f}`,
              group: "Files",
              label: baseName(f),
              keywords: f,
              icon: baseName(f).toLowerCase().endsWith(".enc") ? <FileLock2 size={16} /> : <FileText size={16} />,
              run: () => void handleOpenFile(f),
            }))
            : []),
      ]
      : [];

  const filteredCommands = paletteCommands
      .filter((c) => matchesQuery(`${c.label} ${c.group} ${c.keywords ?? ""}`, paletteQuery))
      .slice(0, 40);

  const runCommand = (command: PaletteCommand | undefined) => {
    if (!command) return;
    setPaletteOpen(false);
    command.run();
  };

  const onPaletteKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setPaletteSel((i) => (filteredCommands.length ? (i + 1) % filteredCommands.length : 0));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setPaletteSel((i) =>
          filteredCommands.length ? (i - 1 + filteredCommands.length) % filteredCommands.length : 0
      );
    } else if (e.key === "Enter") {
      e.preventDefault();
      runCommand(filteredCommands[paletteSel]);
    }
  };

  useEffect(() => {
    document
        .querySelector(".spot-item.selected")
        ?.scrollIntoView({ block: "nearest" });
  }, [paletteSel, searchSel, paletteOpen, isSearchOpen]);

  // ---- Outline navigation -------------------------------------------------
  const jumpToHeading = (domIndex: number) => {
    const target = editorRef.current?.querySelectorAll<HTMLElement>(HEADING_SELECTOR)[domIndex];
    if (!target) return;
    const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    // Hold the clicked heading as active while the smooth scroll runs; a heading near the end
    // of a short note can never reach the top, so the scroll-spy must not override the click.
    spyLockUntil.current = performance.now() + 900;
    target.scrollIntoView({ behavior: reduceMotion ? "auto" : "smooth", block: "start" });
    setActiveHeading(domIndex);
  };

  const onEditorScroll = () => {
    if (spyFrame.current || performance.now() < spyLockUntil.current) return;
    spyFrame.current = window.requestAnimationFrame(() => {
      spyFrame.current = 0;
      const container = scrollRef.current;
      const root = editorRef.current;
      if (!container || !root) return;
      const threshold = container.getBoundingClientRect().top + 96;
      let current = -1;
      root.querySelectorAll<HTMLElement>(HEADING_SELECTOR).forEach((el, index) => {
        if (el.getBoundingClientRect().top <= threshold) current = index;
      });
      setActiveHeading(current);
    });
  };

  // ---- Sidebar resize -----------------------------------------------------
  const onResizeStart = (e: React.PointerEvent) => {
    e.preventDefault();
    const startX = e.clientX;
    const startWidth = sidebarWidth;
    setIsResizing(true);
    const onMove = (ev: PointerEvent) => {
      setSidebarWidth(clamp(startWidth + ev.clientX - startX, SIDEBAR_MIN, SIDEBAR_MAX));
    };
    const onUp = () => {
      setIsResizing(false);
      window.removeEventListener("pointermove", onMove);
      window.removeEventListener("pointerup", onUp);
    };
    window.addEventListener("pointermove", onMove);
    window.addEventListener("pointerup", onUp);
  };

  const onResizeKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "ArrowLeft" || e.key === "ArrowRight") {
      e.preventDefault();
      const delta = e.key === "ArrowLeft" ? -16 : 16;
      setSidebarWidth((w) => clamp(w + delta, SIDEBAR_MIN, SIDEBAR_MAX));
    }
  };

  // Global Keyboard Shortcuts. Registered once in the capture phase so app shortcuts win over
  // the editor's own bindings (e.g. Ctrl+E); the ref always points at the latest handler.
  const keyHandlerRef = useRef<(e: KeyboardEvent) => void>(() => {});
  keyHandlerRef.current = (e: KeyboardEvent) => {
    const key = e.key.toLowerCase();
    const mod = e.ctrlKey || e.metaKey;

    if (e.key === "Escape") {
      if (menuOpen) setMenuOpen(false);
      else if (paletteOpen) closePalette();
      else if (isSearchOpen) closeSearch();
      else if (confirmClosePath !== null) setConfirmClosePath(null);
      else if (vaultModal.mode) closeVault();
      else if (zen) setZen(false);
      else return;
      e.preventDefault();
      e.stopPropagation();
      return;
    }

    if (anyModalOpen) {
      // Only let a modal's own shortcut toggle it; everything else stays with the modal.
      if (mod && !e.shiftKey && key === "k" && paletteOpen) closePalette();
      else if (mod && e.shiftKey && key === "f" && isSearchOpen) closeSearch();
      else return;
      e.preventDefault();
      e.stopPropagation();
      return;
    }

    if (e.key === "F11") {
      setZen((z) => !z);
    } else if (!mod) {
      return;
    } else if (e.shiftKey && key === "f") {
      openSearch();
    } else if (e.shiftKey && key === "l") {
      void lockVault("panic");
    } else if (e.shiftKey && key === "e") {
      setSidebarCollapsed((c) => !c);
    } else if (e.shiftKey) {
      return;
    } else if (key === "k") {
      openPalette();
    } else if (key === "s") {
      void handleSaveCurrentTab();
    } else if (key === "n") {
      handleNewNote();
    } else if (key === "e") {
      void handleExportHtml();
    } else if (key === "l") {
      requestEncrypt();
    } else if (key === "p") {
      handlePrintPdf();
    } else if (key === "w") {
      handleCloseTab(activeTabPath);
    } else if (key === "\\") {
      setZen((z) => !z);
    } else {
      return;
    }
    e.preventDefault();
    e.stopPropagation();
  };

  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => keyHandlerRef.current(e);
    window.addEventListener("keydown", onKeyDown, true);
    return () => window.removeEventListener("keydown", onKeyDown, true);
  }, []);

  const strength = scorePassphrase(vaultPassword);
  // The same dialog encrypts a plain note and re-keys an encrypted one; only the wording differs.
  const isRekey = vaultModal.mode === "encrypt" && !!activeTab?.isEncrypted;
  const confirmTab = tabs.find((t) => t.path === confirmClosePath);
  const canShredOriginal =
      vaultModal.mode === "encrypt" &&
      !!activeTab &&
      isDiskPath(activeTab.path) &&
      (!activeTab.isEncrypted || PLAINTEXT_IMAGE_REF.test(activeTab.content));

  const shellClass = [
    "app-shell",
    `theme-${theme}`,
    IS_NATIVE ? "is-native" : "",
    zen ? "zen" : "",
    sidebarCollapsed ? "sidebar-collapsed" : "",
    isResizing ? "is-resizing" : "",
  ]
      .filter(Boolean)
      .join(" ");

  let lastGroup = "";

  return (
      <div
          className={shellClass}
          style={{ "--sidebar-w": `${sidebarWidth}px` } as React.CSSProperties}
      >
        {/* Top Header / Command Toolbar */}
        <header className="top-toolbar" inert={anyModalOpen || zen}>
          <button
              className={`tb-btn tb-icon ${sidebarCollapsed ? "" : "is-on"}`}
              onClick={() => setSidebarCollapsed((c) => !c)}
              title="Toggle sidebar (Ctrl+Shift+E)"
              aria-label="Toggle sidebar"
              aria-pressed={!sidebarCollapsed}
          >
            <PanelLeft size={16} />
          </button>

          <div className="brand">
            <span className="brand-mark">
              <Zap size={14} strokeWidth={2.4} />
            </span>
            <span className="brand-name">Markseal</span>
          </div>

          <div className="tb-spacer" />

          <button className="palette-trigger" onClick={openPalette} title="Command palette (Ctrl+K)">
            <Command size={14} />
            <span className="pt-label">Search commands and files…</span>
            <span className="kbd">Ctrl+K</span>
          </button>

          <div className="tb-spacer" />

          <div className="tb-actions">
            <button
                className={`tb-btn tb-icon ${justSaved ? "is-saved" : activeTab?.isDirty ? "is-dirty" : ""}`}
                onClick={handleSaveCurrentTab}
                title={activeTab?.isDirty ? "Save changes (Ctrl+S)" : "Save (Ctrl+S)"}
                aria-label="Save"
            >
              {justSaved ? <Check size={16} /> : <Save size={16} />}
            </button>
            <button
                className="tb-btn tb-icon"
                onClick={openSearch}
                title="Search workspace (Ctrl+Shift+F)"
                aria-label="Search workspace"
            >
              <Search size={16} />
            </button>
            <button
                className="tb-btn tb-icon"
                onClick={() => setZen(true)}
                title="Focus mode (Ctrl+\ or F11)"
                aria-label="Enter focus mode"
            >
              <Maximize2 size={16} />
            </button>
            <div className="menu-anchor">
              <button
                  className={`tb-btn tb-icon ${menuOpen ? "is-on" : ""}`}
                  onClick={() => setMenuOpen((o) => !o)}
                  title="More actions"
                  aria-label="More actions"
                  aria-haspopup="menu"
                  aria-expanded={menuOpen}
              >
                <Ellipsis size={16} />
              </button>
              {menuOpen && (
                  <div className="menu" role="menu">
                    <button className="menu-item" role="menuitem" onClick={() => runMenu(() => void handleOpenFolder())}>
                      <FolderOpen size={15} />
                      <span className="mi-label">Open folder…</span>
                    </button>
                    <button className="menu-item" role="menuitem" onClick={() => runMenu(handleNewNote)}>
                      <FilePlus2 size={15} />
                      <span className="mi-label">New note</span>
                      <span className="kbd">Ctrl+N</span>
                    </button>
                    <button className="menu-item" role="menuitem" onClick={() => runMenu(() => void handleExportHtml())}>
                      <FileCode2 size={15} />
                      <span className="mi-label">Export sanitized HTML</span>
                      <span className="kbd">Ctrl+E</span>
                    </button>
                    <button className="menu-item" role="menuitem" onClick={() => runMenu(handlePrintPdf)}>
                      <Printer size={15} />
                      <span className="mi-label">Print / save as PDF</span>
                      <span className="kbd">Ctrl+P</span>
                    </button>
                    <div className="menu-sep" role="separator" />
                    <button className="menu-item" role="menuitem" onClick={() => runMenu(() => void lockVault("panic"))}>
                      <LockKeyhole size={15} />
                      <span className="mi-label">Lock all notes</span>
                      <span className="kbd">Ctrl+Shift+L</span>
                    </button>
                  </div>
              )}
            </div>
          </div>

          <button
              className="tb-btn tb-vault"
              onClick={requestEncrypt}
              title="Zero-Knowledge AES-256-GCM + Argon2id Encryption (Ctrl+L)"
          >
            {activeTab?.isEncrypted ? <LockKeyhole size={15} /> : <Lock size={15} />}
            <span className="tb-label">{activeTab?.isEncrypted ? "Re-key" : "Encrypt"}</span>
          </button>

          <div className="theme-swatches" role="radiogroup" aria-label="Theme">
            {THEMES.map((t) => (
                <button
                    key={t.id}
                    className="swatch"
                    role="radio"
                    aria-checked={theme === t.id}
                    aria-label={t.label}
                    title={t.label}
                    style={{ "--sw-a": t.swatch[0], "--sw-b": t.swatch[1] } as React.CSSProperties}
                    onClick={(e) => {
                      const box = e.currentTarget.getBoundingClientRect();
                      switchTheme(t.id, { x: box.left + box.width / 2, y: box.top + box.height / 2 });
                    }}
                />
            ))}
          </div>
        </header>

        {/* Main Content Split */}
        <div className="workspace-body" inert={anyModalOpen}>
          {/* Left Sidebar: Files & Live Outline */}
          <aside className="sidebar" inert={sidebarCollapsed || zen}>
            <div className="side-section">
              <div className="side-head">
                <span className="side-title">Explorer</span>
                {files.length > 0 && <span className="side-count">{files.length}</span>}
                <button className="icon-btn" onClick={handleOpenFolder} title="Open folder" aria-label="Open folder">
                  <FolderOpen size={14} />
                </button>
                <button className="icon-btn" onClick={handleNewNote} title="New note (Ctrl+N)" aria-label="New note">
                  <Plus size={15} />
                </button>
              </div>
              <div className="side-list">
                {!workspaceRoot ? (
                    <div className="empty-state">
                      <div className="empty-art">
                        <FolderOpen size={24} />
                      </div>
                      <div className="empty-title">No folder open</div>
                      <div className="empty-text">
                        Open a folder to browse, search and encrypt the notes inside it.
                      </div>
                      <button className="btn btn-primary btn-sm" onClick={handleOpenFolder}>
                        <FolderOpen size={14} />
                        Open folder
                      </button>
                    </div>
                ) : files.length === 0 ? (
                    <div className="empty-hint">No Markdown notes in this folder yet.</div>
                ) : (
                    files.map((f, i) => {
                      const shortName = baseName(f);
                      const isEnc = shortName.toLowerCase().endsWith(".enc");
                      return (
                          <button
                              key={f}
                              className={`file-item ${activeTabPath === f ? "active" : ""} ${
                                  isEnc ? "is-enc" : ""
                              }`}
                              style={{ "--i": i } as React.CSSProperties}
                              onClick={() => handleOpenFile(f)}
                              title={f}
                          >
                            <span className="fi-icon">
                              {isEnc ? <FileLock2 size={15} /> : <FileText size={15} />}
                            </span>
                            <span className="fi-name">{shortName}</span>
                            {isEnc && <span className="enc-badge">ENC</span>}
                          </button>
                      );
                    })
                )}
              </div>
            </div>

            <div className="side-section">
              <div className="side-head">
                <span className="side-title">Outline</span>
              </div>
              <div className="side-list">
                {outline.length === 0 ? (
                    <div className="empty-hint">Headings you write appear here.</div>
                ) : (
                    outline.map((h) => (
                        <button
                            key={h.domIndex}
                            className={`outline-item level-${h.level} ${
                                activeHeading === h.domIndex ? "active" : ""
                            }`}
                            onClick={() => jumpToHeading(h.domIndex)}
                            title={h.text}
                        >
                          <span className="oi-text">{h.text}</span>
                        </button>
                    ))
                )}
              </div>
            </div>

            <div
                className="sidebar-resizer"
                role="separator"
                aria-orientation="vertical"
                aria-label="Resize sidebar"
                aria-valuemin={SIDEBAR_MIN}
                aria-valuemax={SIDEBAR_MAX}
                aria-valuenow={sidebarWidth}
                tabIndex={0}
                onPointerDown={onResizeStart}
                onDoubleClick={() => setSidebarWidth(SIDEBAR_DEFAULT)}
                onKeyDown={onResizeKeyDown}
            />
          </aside>

          {/* Center Editor Region */}
          <main className="editor-area">
            {/* Multi-Tab Bar */}
            <div
                className="tab-bar"
                role="tablist"
                ref={tabBarRef}
                inert={zen}
                onWheel={(e) => {
                  if (e.deltaY !== 0) e.currentTarget.scrollLeft += e.deltaY;
                }}
            >
              {tabs.map((tab) => (
                  <div
                      key={tab.path}
                      role="tab"
                      tabIndex={0}
                      aria-selected={tab.path === activeTabPath}
                      className={`tab ${tab.path === activeTabPath ? "active" : ""} ${
                          tab.isDirty ? "dirty" : ""
                      }`}
                      title={tab.path}
                      onClick={() => activateTab(tab.path)}
                      onAuxClick={(e) => {
                        if (e.button === 1) handleCloseTab(tab.path, e);
                      }}
                      onKeyDown={(e) => {
                        if (e.target === e.currentTarget && (e.key === "Enter" || e.key === " ")) {
                          e.preventDefault();
                          activateTab(tab.path);
                        }
                      }}
                  >
                    {tab.isEncrypted && (
                        <span className="tab-lock" title="AES-256-GCM encrypted — decrypted for this session">
                          <LockOpen size={13} />
                        </span>
                    )}
                    <span className="tab-name">{tab.name}</span>
                    <span className="tab-end">
                      {tab.isDirty && <span className="tab-dirty" title="Unsaved changes" />}
                      <button
                          className="tab-close"
                          onClick={(e) => handleCloseTab(tab.path, e)}
                          aria-label={`Close ${tab.name}`}
                      >
                        <X size={13} />
                      </button>
                    </span>
                  </div>
              ))}
              <button className="icon-btn tab-new" onClick={handleNewNote} title="New note (Ctrl+N)" aria-label="New note">
                <Plus size={15} />
              </button>
            </div>

            {zen && (
                <button className="zen-exit" onClick={() => setZen(false)}>
                  <Minimize2 size={13} />
                  Exit focus
                  <span className="kbd">Esc</span>
                </button>
            )}

            {/* Milkdown WYSIWYG Surface */}
            <div className="editor-scroll" ref={scrollRef} onScroll={onEditorScroll}>
              <div ref={editorRef} className="milkdown-surface" />
            </div>
          </main>
        </div>

        {/* Status Bar */}
        <footer className="status-bar" inert={anyModalOpen || zen}>
          <div key={status.id} className={`status-msg tone-${status.tone}`} role="status" aria-live="polite">
            <i className="status-dot" />
            <span title={status.message}>{status.message}</span>
          </div>
          <div className="status-stats">
            <span><b>{stats.words.toLocaleString()}</b> words</span>
            <span className="stat-optional"><b>{stats.chars.toLocaleString()}</b> chars</span>
            <span className="stat-optional"><b>{stats.lines.toLocaleString()}</b> lines</span>
            <span>{stats.minutes === 0 ? "—" : <>~<b>{stats.minutes}</b> min read</>}</span>
          </div>
          {activeTab?.isEncrypted ? (
              <span
                  className="posture is-vault"
                  title={`Zero-Knowledge Vault (AES-256-GCM / Argon2id 64MiB) · ${
                      autoLockMinutes === 0 ? "auto-lock off" : `auto-locks after ${autoLockMinutes} min idle`
                  } · ${shieldActive ? "hidden from screenshots and screen sharing" : "screen-capture shield off"}`}
              >
                <ShieldCheck size={12} />
                AES-256-GCM · Argon2id
                {shieldActive && (
                    <>
                      {" · "}
                      <EyeOff size={12} />
                      Shielded
                    </>
                )}
              </span>
          ) : (
              <span className="posture" title="This note is stored as plain Markdown on disk">
                <FileText size={12} />
                Plaintext
              </span>
          )}
        </footer>

        {/* Shown the instant a lock starts, so nothing secret stays on screen while notes save. */}
        {vaultCurtain && (
            <div className="vault-curtain" role="status">
              <LockKeyhole size={28} />
              <span>Locking…</span>
            </div>
        )}

        {lockToast && (
            <div key={lockToast.id} className={`lock-toast tone-${lockToast.tone}`} role="status" aria-live="assertive">
              <LockKeyhole size={15} />
              <span>{lockToast.message}</span>
            </div>
        )}

        {/* Command Palette (Ctrl+K) */}
        {paletteOpen && (
            <div
                className="modal-backdrop is-spotlight"
                onMouseDown={(e) => {
                  if (e.target === e.currentTarget) closePalette();
                }}
            >
              <div className="modal spotlight" role="dialog" aria-modal="true" aria-label="Command palette">
                <div className="spot-input-row">
                  <Command size={17} />
                  <input
                      className="spot-input"
                      placeholder="Type a command, theme or file name…"
                      value={paletteQuery}
                      onChange={(e) => {
                        setPaletteQuery(e.target.value);
                        setPaletteSel(0);
                      }}
                      onKeyDown={onPaletteKeyDown}
                      autoFocus
                      spellCheck={false}
                  />
                  <span className="kbd">Esc</span>
                </div>
                <div className="spot-list" role="listbox">
                  {filteredCommands.length === 0 ? (
                      <div className="spot-empty">No matching command.</div>
                  ) : (
                      filteredCommands.map((command, index) => {
                        const header = command.group !== lastGroup ? command.group : null;
                        lastGroup = command.group;
                        return (
                            <React.Fragment key={command.id}>
                              {header && <div className="spot-group">{header}</div>}
                              <button
                                  role="option"
                                  aria-selected={index === paletteSel}
                                  className={`spot-item ${index === paletteSel ? "selected" : ""}`}
                                  onMouseMove={() => setPaletteSel(index)}
                                  onClick={() => runCommand(command)}
                              >
                                <span className="si-icon">{command.icon}</span>
                                <span className="si-main">
                                  <div className="si-label">{command.label}</div>
                                </span>
                                {command.shortcut && <span className="kbd">{command.shortcut}</span>}
                              </button>
                            </React.Fragment>
                        );
                      })
                  )}
                </div>
                <div className="spot-foot">
                  <span><span className="kbd">↑</span><span className="kbd">↓</span> navigate</span>
                  <span><span className="kbd">Enter</span> run</span>
                  <span className="sf-right">Type to find files in the open folder</span>
                </div>
              </div>
            </div>
        )}

        {/* Zero-Knowledge Encryption / Decryption Modal */}
        {vaultModal.mode && (
            <div
                className="modal-backdrop"
                onMouseDown={(e) => {
                  if (e.target === e.currentTarget && !vaultBusy) closeVault();
                }}
            >
              <form
                  className="modal"
                  role="dialog"
                  aria-modal="true"
                  aria-labelledby="vault-title"
                  onSubmit={handleConfirmVaultAction}
              >
                <div className="modal-body">
                  <div className="modal-head">
                    <div className="modal-icon">
                      {vaultModal.mode === "encrypt" ? <Lock size={18} /> : <LockOpen size={18} />}
                    </div>
                    <div>
                      <h3 className="modal-title" id="vault-title">
                        {isRekey
                            ? "Change passphrase"
                            : vaultModal.mode === "encrypt"
                                ? "Encrypt note with Zero-Knowledge Vault"
                                : "Unlock encrypted note"}
                      </h3>
                      <p className="modal-sub">
                        {isRekey
                            ? "The note and its images are encrypted again under the new passphrase, and the old one stops working. Without the new passphrase, recovery is mathematically impossible."
                            : vaultModal.mode === "encrypt"
                                ? "Derived via Argon2id (64 MiB RAM) & encrypted with AES-256-GCM. Without this passphrase, recovery is mathematically impossible."
                                : `Enter passphrase to decrypt: ${baseName(vaultModal.targetPath)}`}
                      </p>
                    </div>
                  </div>

                  <div className="field">
                    <label className="field-label" htmlFor="vault-pass">
                      {isRekey ? "New passphrase" : "Passphrase"}
                    </label>
                    <div className="input-wrap">
                      <input
                          id="vault-pass"
                          type={showPassphrase ? "text" : "password"}
                          className="text-input"
                          placeholder={
                            vaultModal.mode === "encrypt"
                                ? "At least 8 characters"
                                : "Enter passphrase"
                          }
                          value={vaultPassword}
                          onChange={(e) => {
                            setVaultPassword(e.target.value);
                            setVaultError("");
                          }}
                          autoComplete="off"
                          spellCheck={false}
                          autoFocus
                          required
                      />
                      <button
                          type="button"
                          className="icon-btn"
                          onClick={() => setShowPassphrase((s) => !s)}
                          aria-label={showPassphrase ? "Hide passphrase" : "Show passphrase"}
                          title={showPassphrase ? "Hide passphrase" : "Show passphrase"}
                      >
                        {showPassphrase ? <EyeOff size={15} /> : <Eye size={15} />}
                      </button>
                    </div>
                    {vaultModal.mode === "encrypt" && (
                        <div className="strength" data-score={strength}>
                          <div className="strength-bars" aria-hidden="true">
                            <i /><i /><i /><i />
                          </div>
                          <span className="strength-label">
                            {strength === 0 ? "Strength" : STRENGTH_LABELS[strength]}
                          </span>
                        </div>
                    )}
                  </div>

                  {vaultModal.mode === "encrypt" && (
                      <>
                        <div className="field">
                          <label className="field-label" htmlFor="vault-confirm">
                            {isRekey ? "Confirm new passphrase" : "Confirm passphrase"}
                          </label>
                          <div className="input-wrap">
                            <input
                                id="vault-confirm"
                                type={showPassphrase ? "text" : "password"}
                                className="text-input"
                                placeholder="Type it again"
                                value={vaultConfirm}
                                onChange={(e) => {
                                  setVaultConfirm(e.target.value);
                                  setVaultError("");
                                }}
                                autoComplete="off"
                                spellCheck={false}
                                required
                            />
                          </div>
                          {vaultConfirm.length > 0 &&
                              (vaultConfirm === vaultPassword ? (
                                  <div className="field-hint is-ok">
                                    <Check size={13} /> Passphrases match
                                  </div>
                              ) : (
                                  <div className="field-hint is-bad">
                                    <X size={13} /> Passphrases do not match yet
                                  </div>
                              ))}
                        </div>

                        {canShredOriginal && (
                            <>
                              <label className="check-row">
                                <input
                                    type="checkbox"
                                    checked={shredOriginal}
                                    onChange={(e) => setShredOriginal(e.target.checked)}
                                />
                                <span>Overwrite &amp; delete the unencrypted originals — the .md file and its images (best-effort on SSDs)</span>
                              </label>
                              <p className="fine-print">
                                Single-pass overwrite cannot guarantee physical block erasure on SSDs, NVMe,
                                or copy-on-write filesystems due to wear leveling.
                              </p>
                            </>
                        )}
                      </>
                  )}

                  {vaultError && (
                      <div className="modal-error" role="alert">
                        <CircleAlert size={15} />
                        <span>{vaultError}</span>
                      </div>
                  )}

                  <div className="modal-actions">
                    <button type="button" className="btn" onClick={closeVault} disabled={vaultBusy}>
                      Cancel
                    </button>
                    <button type="submit" className="btn btn-primary" disabled={vaultBusy}>
                      {vaultBusy
                          ? "Deriving key…"
                          : isRekey
                              ? "Change passphrase"
                              : vaultModal.mode === "encrypt"
                                  ? "Encrypt & Save"
                                  : "Decrypt & Open"}
                    </button>
                  </div>
                </div>
              </form>
            </div>
        )}

        {/* Workspace Search Modal (Ctrl+Shift+F) */}
        {isSearchOpen && (
            <div
                className="modal-backdrop is-spotlight"
                onMouseDown={(e) => {
                  if (e.target === e.currentTarget) closeSearch();
                }}
            >
              <div className="modal spotlight" role="dialog" aria-modal="true" aria-label="Search workspace">
                <div className="spot-input-row">
                  <Search size={17} />
                  <input
                      type="text"
                      className="spot-input"
                      placeholder="Search across all plaintext notes…"
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      onKeyDown={onSearchKeyDown}
                      autoFocus
                      spellCheck={false}
                  />
                  <button
                      type="button"
                      className="toggle-chip"
                      aria-pressed={caseSensitive}
                      onClick={() => setCaseSensitive((c) => !c)}
                      title="Case sensitive"
                  >
                    <CaseSensitive size={15} />
                  </button>
                  <span className="kbd">Esc</span>
                </div>
                <div className="spot-list" role="listbox">
                  {!workspaceRoot ? (
                      <div className="spot-empty">Open a folder first — search runs across its notes.</div>
                  ) : searchState === "error" ? (
                      <div className="spot-empty" style={{ color: "var(--danger)" }}>
                        Search error: {searchError}
                      </div>
                  ) : searchQuery.trim().length < 2 ? (
                      <div className="spot-empty">Type at least 2 characters.</div>
                  ) : searchState === "busy" && visibleResults.length === 0 ? (
                      <div className="spot-empty">Searching…</div>
                  ) : visibleResults.length === 0 ? (
                      <div className="spot-empty">No matches in plaintext notes.</div>
                  ) : (
                      visibleResults.map((m, idx) => (
                          <button
                              key={`${m.file_path}:${m.line_number}:${idx}`}
                              role="option"
                              aria-selected={idx === searchSel}
                              className={`spot-item ${idx === searchSel ? "selected" : ""}`}
                              onMouseMove={() => setSearchSel(idx)}
                              onClick={() => openSearchResult(m)}
                          >
                            <span className="si-icon"><FileText size={16} /></span>
                            <span className="si-main">
                              <div className="si-label si-file">
                                {baseName(m.file_path)}:{m.line_number}
                              </div>
                              <div className="si-sub">
                                <Highlighted text={m.snippet} query={searchQuery} caseSensitive={caseSensitive} />
                              </div>
                            </span>
                          </button>
                      ))
                  )}
                </div>
                <div className="spot-foot">
                  <span><span className="kbd">↑</span><span className="kbd">↓</span> navigate</span>
                  <span><span className="kbd">Enter</span> open <CornerDownLeft size={12} /></span>
                  <span className="sf-right">
                    {searchResults.length > MAX_SEARCH_ROWS
                        ? `Showing first ${MAX_SEARCH_ROWS} of ${searchResults.length} · `
                        : searchResults.length > 0
                            ? `${searchResults.length} match${searchResults.length === 1 ? "" : "es"} · `
                            : ""}
                    Encrypted .enc vaults are excluded
                  </span>
                </div>
              </div>
            </div>
        )}

        {/* Unsaved-changes guard */}
        {confirmTab && (
            <div
                className="modal-backdrop"
                onMouseDown={(e) => {
                  if (e.target === e.currentTarget) setConfirmClosePath(null);
                }}
            >
              <div className="modal" role="alertdialog" aria-modal="true" aria-labelledby="confirm-title">
                <div className="modal-body">
                  <div className="modal-head">
                    <div className="modal-icon is-danger">
                      <TriangleAlert size={18} />
                    </div>
                    <div>
                      <h3 className="modal-title" id="confirm-title">Discard unsaved changes?</h3>
                      <p className="modal-sub">
                        “{confirmTab.name}” has edits that were never saved. Closing the tab loses them.
                      </p>
                    </div>
                  </div>
                  <div className="modal-actions">
                    <button className="btn" onClick={() => setConfirmClosePath(null)} autoFocus>
                      Keep editing
                    </button>
                    <button
                        className="btn btn-danger"
                        onClick={() => {
                          const path = confirmTab.path;
                          setConfirmClosePath(null);
                          closeTabNow(path);
                        }}
                    >
                      Discard &amp; close
                    </button>
                  </div>
                </div>
              </div>
            </div>
        )}
      </div>
  );
}
