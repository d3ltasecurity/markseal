import { useEffect, useRef } from "react";
import { Crepe } from "@milkdown/crepe";
import { oneDark } from "@codemirror/theme-one-dark";
import { EditorView } from "@codemirror/view";
import { invoke, convertFileSrc } from "@tauri-apps/api/core";
import "@milkdown/crepe/theme/common/style.css";
import "@milkdown/crepe/theme/frame-dark.css";

export type EditorTheme = "dark-cyber" | "nord-minimal" | "github-light" | "matrix-green";

interface CrepeEditorProps {
  docId: string;
  initialContent: string;
  activeFilePath?: string;
  readOnly: boolean;
  theme: EditorTheme;
  onChange: (markdown: string) => void;
}

let mermaidIdCounter = 0;

function isDarkTheme(theme: EditorTheme): boolean {
  return theme !== "github-light";
}

function lightCodeMirrorTheme() {
  return EditorView.theme(
    {
      "&": { backgroundColor: "#ffffff", color: "#1f2328" },
      ".cm-content": { caretColor: "#0969da" },
      ".cm-cursor, .cm-dropCursor": { borderLeftColor: "#0969da" },
      ".cm-gutters": { backgroundColor: "#f6f8fa", color: "#656d76", border: "none" },
      ".cm-activeLine, .cm-activeLineGutter": { backgroundColor: "#eaeef2" },
    },
    { dark: false },
  );
}

function dirName(path: string): string {
  const idx = Math.max(path.lastIndexOf("\\"), path.lastIndexOf("/"));
  return idx >= 0 ? path.slice(0, idx) : path;
}

function isRemoteUrl(url: string): boolean {
  return /^(https?:|data:|blob:|asset:|http:\/\/asset\.localhost)/i.test(url);
}

function extensionOf(file: File): string {
  const fromName = file.name.includes(".") ? file.name.split(".").pop() : "";
  if (fromName) return fromName.toLowerCase();
  const fromType = file.type.split("/")[1];
  return (fromType || "png").replace("jpeg", "jpg").split("+")[0];
}

export default function CrepeEditor({
  docId,
  initialContent,
  activeFilePath,
  readOnly,
  theme,
  onChange,
}: CrepeEditorProps) {
  const rootRef = useRef<HTMLDivElement>(null);
  const crepeRef = useRef<Crepe | null>(null);
  const onChangeRef = useRef(onChange);
  const pathRef = useRef(activeFilePath);
  const readOnlyRef = useRef(readOnly);
  const lastEmittedRef = useRef(initialContent);
  const themeRef = useRef(theme);

  onChangeRef.current = onChange;
  pathRef.current = activeFilePath;
  readOnlyRef.current = readOnly;
  themeRef.current = theme;

  // (Re)create the editor whenever the document changes.
  useEffect(() => {
    const root = rootRef.current;
    if (!root) return;

    let disposed = false;
    lastEmittedRef.current = initialContent;

    const upload = async (file: File): Promise<string> => {
      const mdPath = pathRef.current;
      if (mdPath) {
        const bytes = Array.from(new Uint8Array(await file.arrayBuffer()));
        return await invoke<string>("save_pasted_image", {
          activeMdPath: mdPath,
          imageBytes: bytes,
          extension: extensionOf(file),
        });
      }
      return URL.createObjectURL(file);
    };

    const crepe = new Crepe({
      root,
      defaultValue: initialContent,
      features: {
        [Crepe.Feature.CodeMirror]: true,
        [Crepe.Feature.Latex]: true,
      },
      featureConfigs: {
        [Crepe.Feature.CodeMirror]: {
          theme: isDarkTheme(themeRef.current) ? oneDark : lightCodeMirrorTheme(),
          renderPreview: (language, content, applyPreview) => {
            if (language.toLowerCase() !== "mermaid") return null;

            const loading = document.createElement("div");
            loading.className = "mermaid-preview-loading";
            loading.textContent = "Rendering diagram…";
            const id = `markforge-mermaid-${++mermaidIdCounter}`;
            const dark = isDarkTheme(themeRef.current);

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
        [Crepe.Feature.Latex]: {
          katexOptions: { throwOnError: false },
        },
        [Crepe.Feature.ImageBlock]: {
          onUpload: upload,
          blockOnUpload: upload,
          inlineOnUpload: upload,
          // Resolve saved relative paths (assets/...) against the note's folder.
          proxyDomURL: (url: string) => {
            const mdPath = pathRef.current;
            if (!mdPath || isRemoteUrl(url)) return url;
            const sep = mdPath.includes("\\") ? "\\" : "/";
            const abs = `${dirName(mdPath)}${sep}${url.replace(/^\.?[\\/]/, "").replace(/[\\/]/g, sep)}`;
            return convertFileSrc(abs);
          },
        },
      },
    });

    crepe.on((listener) => {
      listener.markdownUpdated((_ctx, markdown, prevMarkdown) => {
        if (markdown === prevMarkdown) return;
        lastEmittedRef.current = markdown;
        onChangeRef.current(markdown);
      });
    });

    crepe
      .create()
      .then(() => {
        if (disposed) {
          void crepe.destroy();
          return;
        }
        crepeRef.current = crepe;
        crepe.setReadonly(readOnlyRef.current);
      })
      .catch((err) => console.error("Failed to create editor", err));

    return () => {
      disposed = true;
      if (crepeRef.current === crepe) crepeRef.current = null;
      void crepe.destroy().catch(() => undefined);
    };
    // initialContent is intentionally only read when the document changes.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [docId, theme]);

  // Dynamically toggle read-only state.
  useEffect(() => {
    crepeRef.current?.setReadonly(readOnly);
  }, [readOnly]);

  return <div className="crepe-editor milkdown-host" ref={rootRef} />;
}
