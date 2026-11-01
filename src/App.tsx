import React, { useState, useEffect, useRef, useCallback } from "react";
import { invoke, convertFileSrc } from "@tauri-apps/api/core";
import { open, save } from "@tauri-apps/plugin-dialog";
import { Crepe } from "@milkdown/crepe";
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

type ThemeName = "dark" | "light" | "nord" | "solarized";

export default function App() {
  const [workspaceRoot, setWorkspaceRoot] = useState<string>("");
  const [files, setFiles] = useState<string[]>([]);
  const [tabs, setTabs] = useState<OpenTab[]>([
    {
      path: "Untitled-1.md",
      name: "Untitled-1.md",
      content:
          "# Welcome to MarkForge 🛡️\n\nHigh-performance, **zero-knowledge** native Markdown editor.\n\nPress `Ctrl+L` to **Encrypt / Lock** any note with `AES-256-GCM` + `Argon2id`.\nPress `Ctrl+E` to **Export Standalone Sanitized HTML**.\nPress `Ctrl+P` to **Print / Export to PDF**.\nPress `Ctrl+Shift+F` for **Workspace Search**.\nPress `Ctrl+N` for **New Note**.\n",
      isDirty: false,
      isEncrypted: false,
    },
  ]);
  const [activeTabPath, setActiveTabPath] = useState<string>("Untitled-1.md");
  const [theme, setTheme] = useState<ThemeName>("dark");
  const [outline, setOutline] = useState<{ level: number; text: string }[]>([]);

  // Search Modal State
  const [isSearchOpen, setIsSearchOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const [caseSensitive, setCaseSensitive] = useState(false);
  const [searchResults, setSearchResults] = useState<SearchMatch[]>([]);

  // Vault Encryption / Decryption Modal State
  const [vaultModal, setVaultModal] = useState<{
    mode: "encrypt" | "decrypt" | null;
    targetPath: string;
  }>({ mode: null, targetPath: "" });
  const [vaultPassword, setVaultPassword] = useState("");
  const [vaultConfirm, setVaultConfirm] = useState("");
  const [shredOriginal, setShredOriginal] = useState(true);
  const [statusMessage, setStatusMessage] = useState<string>("Ready");

  const editorRef = useRef<HTMLDivElement | null>(null);
  const crepeRef = useRef<Crepe | null>(null);
  const themeRef = useRef(theme);
  themeRef.current = theme;
  const activeTab = tabs.find((t) => t.path === activeTabPath) || tabs[0];

  // Parse headings for live Outline
  const updateOutline = useCallback((markdown: string) => {
    const lines = markdown.split("\n");
    const headings: { level: number; text: string }[] = [];
    for (const line of lines) {
      const match = line.match(/^(#{1,4})\s+(.+)$/);
      if (match) {
        headings.push({ level: match[1].length, text: match[2].trim() });
      }
    }
    setOutline(headings);
  }, []);

  // Initialize / Rebuild Milkdown Crepe on active tab switch
  useEffect(() => {
    if (!editorRef.current || !activeTab) return;

    let destroyed = false;
    editorRef.current.innerHTML = "";

    const upload = async (file: File): Promise<string> => {
      const mdPath = activeTab?.path;
      if (mdPath && (mdPath.includes("/") || mdPath.includes("\\"))) {
        const bytes = Array.from(new Uint8Array(await file.arrayBuffer()));
        const ext = file.name.includes(".") ? file.name.split(".").pop() || "png" : "png";
        return await invoke<string>("save_pasted_image", {
          activeMdPath: mdPath,
          imageBytes: bytes,
          extension: ext,
        });
      }
      return URL.createObjectURL(file);
    };

    let mermaidIdCounter = 0;
    const crepe = new Crepe({
      root: editorRef.current,
      defaultValue: activeTab.content,
      features: {
        [Crepe.Feature.CodeMirror]: true,
        [Crepe.Feature.Latex]: true,
      },
      featureConfigs: {
        [Crepe.Feature.CodeMirror]: {
          renderPreview: (language, content, applyPreview) => {
            if (language.toLowerCase() !== "mermaid") return null;

            const loading = document.createElement("div");
            loading.className = "mermaid-preview-loading";
            loading.textContent = "Rendering diagram…";
            const id = `markforge-mermaid-${++mermaidIdCounter}`;
            const dark = themeRef.current !== "light";

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
            return convertFileSrc(abs);
          },
        },
      },
    });

    crepe.create().then(() => {
      if (destroyed) {
        crepe.destroy();
        return;
      }
      crepeRef.current = crepe;
      updateOutline(activeTab.content);
    });

    return () => {
      destroyed = true;
      if (crepeRef.current) {
        crepeRef.current.destroy();
        crepeRef.current = null;
      }
    };
  }, [activeTabPath]);

  const syncCurrentEditorContent = (): string => {
    if (!crepeRef.current) return activeTab?.content || "";
    try {
      const md = crepeRef.current.getMarkdown();
      updateOutline(md);
      return md;
    } catch {
      return activeTab?.content || "";
    }
  };

  const refreshWorkspace = async (rootPath: string) => {
    try {
      const list = await invoke<string[]>("list_markdown_files", {
        dirPath: rootPath,
      });
      setFiles(list);
    } catch (err) {
      setStatusMessage(`Workspace Error: ${err}`);
    }
  };

  const handleOpenFolder = async () => {
    const selected = await open({ directory: true, multiple: false });
    if (typeof selected === "string") {
      setWorkspaceRoot(selected);
      try {
        await invoke("set_workspace_root", { dirPath: selected });
      } catch (e) {
        console.warn("set_workspace_root notice:", e);
      }
      await refreshWorkspace(selected);
      setStatusMessage(`Opened workspace: ${selected}`);
    }
  };

  // Handler to create a brand new note
  const handleNewNote = async () => {
    const timestamp = Date.now();
    const newName = `note_${timestamp}.md`;
    const newPath = workspaceRoot ? `${workspaceRoot}\\${newName}` : newName;
    const initialContent = "# Untitled Note\n\nStart writing here...";

    const newTab: OpenTab = {
      path: newPath,
      name: newName,
      content: initialContent,
      isDirty: false,
      isEncrypted: false,
    };

    setTabs((prev) => [...prev, newTab]);
    setActiveTabPath(newPath);
    setStatusMessage(`Created new note: ${newName}`);
  };

  const handleOpenFile = async (filePath: string) => {
    const existing = tabs.find((t) => t.path === filePath);
    if (existing) {
      setActiveTabPath(filePath);
      return;
    }

    try {
      const encrypted = await invoke<boolean>("is_encrypted_note", { filePath });
      if (encrypted) {
        setVaultPassword("");
        setVaultModal({ mode: "decrypt", targetPath: filePath });
        return;
      }

      const content = await invoke<string>("read_markdown_file", { filePath });
      const name = filePath.split(/[\\/]/).pop() || filePath;
      setTabs((prev) => [
        ...prev,
        { path: filePath, name, content, isDirty: false, isEncrypted: false },
      ]);
      setActiveTabPath(filePath);
      setStatusMessage(`Loaded ${name}`);
    } catch (err) {
      setStatusMessage(`Read Error: ${err}`);
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
          setVaultPassword("");
          setVaultConfirm("");
          setVaultModal({ mode: "encrypt", targetPath });
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

      const newName = targetPath.split(/[\\/]/).pop() || targetPath;
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
      setStatusMessage(
          activeTab.isEncrypted
              ? `🔒 Saved Encrypted Vault: ${newName}`
              : `Saved: ${newName}`
      );
    } catch (err) {
      setStatusMessage(`Save Error: ${err}`);
    }
  };

  // Vault Encryption / Decryption Handlers
  const handleConfirmVaultAction = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!vaultModal.mode) return;

    if (vaultModal.mode === "decrypt") {
      try {
        const plaintext = await invoke<string>("read_encrypted_markdown", {
          filePath: vaultModal.targetPath,
          password: vaultPassword,
        });
        const name =
            vaultModal.targetPath.split(/[\\/]/).pop() || vaultModal.targetPath;
        setTabs((prev) => [
          ...prev,
          {
            path: vaultModal.targetPath,
            name,
            content: plaintext,
            isDirty: false,
            isEncrypted: true,
            sessionPassword: vaultPassword,
          },
        ]);
        setActiveTabPath(vaultModal.targetPath);
        setVaultPassword("");
        setVaultModal({ mode: null, targetPath: "" });
        setStatusMessage(`🔓 Decrypted vault note: ${name}`);
      } catch (err) {
        setStatusMessage(`❌ ${err}`);
      }
    } else if (vaultModal.mode === "encrypt") {
      if (vaultPassword.length < 8) {
        setStatusMessage("⚠️ Passphrase must be at least 8 characters.");
        return;
      }
      if (vaultPassword !== vaultConfirm) {
        setStatusMessage("⚠️ Passphrases do not match.");
        return;
      }

      const latestMarkdown = syncCurrentEditorContent();
      let encPath = vaultModal.targetPath;
      if (!encPath.includes("/") && !encPath.includes("\\")) {
        const chosen = await save({
          defaultPath: `${activeTab.name.replace(/\.md$/i, "")}.md.enc`,
          filters: [{ name: "MarkForge Encrypted Vault", extensions: ["enc"] }],
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

      try {
        await invoke("save_encrypted_markdown", {
          filePath: encPath,
          content: latestMarkdown,
          password: vaultPassword,
        });

        if (
            shredOriginal &&
            activeTab.path !== encPath &&
            (activeTab.path.includes("/") || activeTab.path.includes("\\"))
        ) {
          await invoke("delete_note_file", { filePath: activeTab.path });
        }

        const newName = encPath.split(/[\\/]/).pop() || encPath;
        setTabs((prev) =>
            prev.map((t) =>
                t.path === activeTab.path
                    ? {
                      path: encPath,
                      name: newName,
                      content: latestMarkdown,
                      isDirty: false,
                      isEncrypted: true,
                      sessionPassword: vaultPassword,
                    }
                    : t
            )
        );
        setActiveTabPath(encPath);
        setVaultPassword("");
        setVaultConfirm("");
        setVaultModal({ mode: null, targetPath: "" });
        if (workspaceRoot) await refreshWorkspace(workspaceRoot);
        setStatusMessage(`🔒 Encrypted with AES-256-GCM + Argon2id: ${newName}`);
      } catch (err) {
        setStatusMessage(`Encryption Error: ${err}`);
      }
    }
  };

  const handleCloseTab = (pathToClose: string, e?: React.MouseEvent) => {
    e?.stopPropagation();
    const remaining = tabs.filter((t) => t.path !== pathToClose);
    if (remaining.length === 0) {
      const fallback: OpenTab = {
        path: "Untitled-1.md",
        name: "Untitled-1.md",
        content: "# New Note\n",
        isDirty: false,
        isEncrypted: false,
      };
      setTabs([fallback]);
      setActiveTabPath(fallback.path);
    } else {
      setTabs(remaining);
      if (activeTabPath === pathToClose) {
        setActiveTabPath(remaining[remaining.length - 1].path);
      }
    }
  };

  const handleExportHtml = async () => {
    if (!activeTab) return;
    const latestMarkdown = syncCurrentEditorContent();
    const defaultHtmlName = `${activeTab.name.replace(/(\.md)?(\.enc)?$/i, "")}.html`;

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

    try {
      await invoke("export_to_html", {
        targetPath,
        markdownContent: latestMarkdown,
        title: activeTab.name.replace(/(\.md)?(\.enc)?$/i, ""),
        theme,
      });
      setStatusMessage(`🌐 Exported sanitized HTML: ${targetPath}`);
    } catch (err) {
      setStatusMessage(`HTML Export Error: ${err}`);
    }
  };

  const handlePrintPdf = () => {
    window.print();
  };

  const runWorkspaceSearch = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!workspaceRoot || !searchQuery.trim()) return;
    try {
      const matches = await invoke<SearchMatch[]>("search_workspace", {
        workspaceRoot,
        query: searchQuery,
        caseSensitive,
      });
      setSearchResults(matches);
    } catch (err) {
      setStatusMessage(`Search Error: ${err}`);
    }
  };

  // Global Keyboard Shortcuts
  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.ctrlKey && e.key.toLowerCase() === "s") {
        e.preventDefault();
        handleSaveCurrentTab();
      } else if (e.ctrlKey && e.key.toLowerCase() === "n") {
        e.preventDefault();
        handleNewNote();
      } else if (e.ctrlKey && e.shiftKey && e.key.toLowerCase() === "f") {
        e.preventDefault();
        setIsSearchOpen((prev) => !prev);
      } else if (e.ctrlKey && e.key.toLowerCase() === "e") {
        e.preventDefault();
        handleExportHtml();
      } else if (e.ctrlKey && e.key.toLowerCase() === "l") {
        e.preventDefault();
        if (activeTab) {
          setVaultPassword("");
          setVaultConfirm("");
          setVaultModal({ mode: "encrypt", targetPath: activeTab.path });
        }
      } else if (e.ctrlKey && e.key.toLowerCase() === "p") {
        e.preventDefault();
        handlePrintPdf();
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  });

  return (
      <div className={`app-shell theme-${theme}`}>
        {/* Top Header / Security & Export Toolbar */}
        <header className="top-toolbar">
          <div className="brand-group">
            <span className="brand-logo">⚡ MarkForge</span>
            <button className="btn-action" onClick={handleOpenFolder}>
              📂 Open Folder
            </button>
            <button className="btn-action" onClick={handleNewNote}>
              📄 New Note (Ctrl+N)
            </button>
            <button className="btn-action" onClick={handleSaveCurrentTab}>
              💾 Save (Ctrl+S)
            </button>
            <button
                className="btn-action btn-vault"
                onClick={() => {
                  if (!activeTab) return;
                  setVaultPassword("");
                  setVaultConfirm("");
                  setVaultModal({ mode: "encrypt", targetPath: activeTab.path });
                }}
                title="Zero-Knowledge AES-256-GCM + Argon2id Encryption (Ctrl+L)"
            >
              {activeTab?.isEncrypted ? "🔒 Re-Key Vault" : "🛡️ Encrypt Note (Ctrl+L)"}
            </button>
          </div>

          <div className="toolbar-right">
            <button
                className="btn-action"
                onClick={() => setIsSearchOpen(true)}
                title="Search Workspace (Ctrl+Shift+F)"
            >
              🔍 Search
            </button>
            <button
                className="btn-action"
                onClick={handleExportHtml}
                title="Export Sanitized HTML (Ctrl+E)"
            >
              🌐 Export HTML
            </button>
            <button
                className="btn-action"
                onClick={handlePrintPdf}
                title="Print or Save as PDF (Ctrl+P)"
            >
              📄 Print / PDF
            </button>

            <select
                className="theme-select"
                value={theme}
                onChange={(e) => setTheme(e.target.value as ThemeName)}
            >
              <option value="dark">Cyber Dark (Mica)</option>
              <option value="nord">Nord Frost</option>
              <option value="light">Clean Light</option>
              <option value="solarized">Solarized Warm</option>
            </select>
          </div>
        </header>

        {/* Main Content Split */}
        <div className="workspace-body">
          {/* Left Sidebar: Files & Live Outline */}
          <aside className="sidebar">
            <div className="sidebar-section">
              <div className="sidebar-title flex items-center justify-between">
                <span>EXPLORER</span>
                <button
                    onClick={handleNewNote}
                    className="text-xs px-1.5 py-0.5 bg-blue-600 hover:bg-blue-700 text-white rounded"
                    title="New Note"
                >
                  + New
                </button>
              </div>
              <div className="file-list">
                {files.length === 0 ? (
                    <div className="empty-hint">No folder opened</div>
                ) : (
                    files.map((f) => {
                      const shortName = f.split(/[\\/]/).pop() || f;
                      const isEnc = shortName.toLowerCase().endsWith(".enc");
                      return (
                          <div
                              key={f}
                              className={`file-item ${
                                  activeTabPath === f ? "active" : ""
                              }`}
                              onClick={() => handleOpenFile(f)}
                          >
                            <span>{isEnc ? "🔒" : "📝"}</span>
                            <span className="file-name">{shortName}</span>
                          </div>
                      );
                    })
                )}
              </div>
            </div>

            <div className="sidebar-section outline-section">
              <div className="sidebar-title">DOCUMENT OUTLINE</div>
              <div className="outline-list">
                {outline.map((h, i) => (
                    <div
                        key={i}
                        className={`outline-item level-${h.level}`}
                    >
                      {h.text}
                    </div>
                ))}
              </div>
            </div>
          </aside>

          {/* Center Editor Region */}
          <main className="editor-area">
            {/* Multi-Tab Bar */}
            <div className="tab-bar">
              {tabs.map((tab) => (
                  <div
                      key={tab.path}
                      className={`tab-pill ${
                          tab.path === activeTabPath ? "active" : ""
                      }`}
                      onClick={() => {
                        const updated = syncCurrentEditorContent();
                        setTabs((prev) =>
                            prev.map((t) =>
                                t.path === activeTabPath ? { ...t, content: updated } : t
                            )
                        );
                        setActiveTabPath(tab.path);
                      }}
                  >
                    {tab.isEncrypted && (
                        <span className="lock-badge" title="AES-256-GCM Encrypted">
                    🔒
                  </span>
                    )}
                    <span>{tab.name}</span>
                    <button
                        className="tab-close"
                        onClick={(e) => handleCloseTab(tab.path, e)}
                    >
                      ×
                    </button>
                  </div>
              ))}
            </div>

            {/* Milkdown WYSIWYG Surface */}
            <div className="editor-scroll-container">
              <div ref={editorRef} className="milkdown-surface" />
            </div>
          </main>
        </div>

        {/* Status Bar */}
        <footer className="status-bar">
          <span>{statusMessage}</span>
          <span>
          {activeTab?.isEncrypted
              ? "🛡️ Zero-Knowledge Vault (AES-256-GCM / Argon2id 64MiB)"
              : "Standard Markdown"}
        </span>
        </footer>

        {/* Zero-Knowledge Encryption / Decryption Modal */}
        {vaultModal.mode && (
            <div className="modal-backdrop">
              <form className="vault-modal" onSubmit={handleConfirmVaultAction}>
                <h3>
                  {vaultModal.mode === "encrypt"
                      ? "🔒 Encrypt Note with Zero-Knowledge Vault"
                      : "🔓 Unlock Encrypted Note"}
                </h3>
                <p className="vault-subtitle">
                  {vaultModal.mode === "encrypt"
                      ? "Derived via Argon2id (64 MiB RAM) & encrypted with AES-256-GCM. Without this passphrase, recovery is mathematically impossible."
                      : `Enter passphrase to decrypt: ${vaultModal.targetPath
                          .split(/[\\/]/)
                          .pop()}`}
                </p>

                <input
                    type="password"
                    className="vault-input"
                    placeholder="Enter passphrase (min 8 chars)..."
                    value={vaultPassword}
                    onChange={(e) => setVaultPassword(e.target.value)}
                    autoFocus
                    required
                />

                {vaultModal.mode === "encrypt" && (
                    <>
                      <input
                          type="password"
                          className="vault-input"
                          placeholder="Confirm passphrase..."
                          value={vaultConfirm}
                          onChange={(e) => setVaultConfirm(e.target.value)}
                          required
                      />
                      <label className="shred-checkbox">
                        <input
                            type="checkbox"
                            checked={shredOriginal}
                            onChange={(e) => setShredOriginal(e.target.checked)}
                        />
                        Overwrite & delete original unencrypted .md file (best-effort on SSDs)
                      </label>
                      <small style={{ color: "#8b949e", fontSize: "0.76rem", display: "block", marginTop: "2px", marginBottom: "6px" }}>
                        (Note: Single-pass overwrite cannot guarantee physical block erasure on SSDs, NVMe, or copy-on-write filesystems due to wear leveling.)
                      </small>
                    </>
                )}

                <div className="modal-actions">
                  <button
                      type="button"
                      className="btn-cancel"
                      onClick={() => {
                        setVaultPassword("");
                        setVaultConfirm("");
                        setVaultModal({ mode: null, targetPath: "" });
                      }}
                  >
                    Cancel
                  </button>
                  <button type="submit" className="btn-confirm">
                    {vaultModal.mode === "encrypt"
                        ? "Encrypt & Save"
                        : "Decrypt & Open"}
                  </button>
                </div>
              </form>
            </div>
        )}

        {/* Workspace Search Modal (Ctrl+Shift+F) */}
        {isSearchOpen && (
            <div className="modal-backdrop">
              <div className="vault-modal search-modal">
                <h3>🔍 Search Workspace</h3>
                <form onSubmit={runWorkspaceSearch} className="search-bar-row">
                  <input
                      type="text"
                      className="vault-input"
                      placeholder="Search across all plaintext notes..."
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      autoFocus
                  />
                  <button type="submit" className="btn-confirm">
                    Find
                  </button>
                  <button
                      type="button"
                      className="btn-cancel"
                      onClick={() => setIsSearchOpen(false)}
                  >
                    Close
                  </button>
                </form>
                <label className="shred-checkbox">
                  <input
                      type="checkbox"
                      checked={caseSensitive}
                      onChange={(e) => setCaseSensitive(e.target.checked)}
                  />
                  Case Sensitive (Encrypted `.enc` vaults are automatically excluded)
                </label>
                <div className="search-results-list">
                  {searchResults.map((m, idx) => (
                      <div
                          key={idx}
                          className="search-result-item"
                          onClick={() => {
                            setIsSearchOpen(false);
                            handleOpenFile(m.file_path);
                          }}
                      >
                        <div className="search-file">
                          {m.file_path.split(/[\\/]/).pop()}:{m.line_number}
                        </div>
                        <div className="search-snippet">{m.snippet}</div>
                      </div>
                  ))}
                </div>
              </div>
            </div>
        )}
      </div>
  );
}