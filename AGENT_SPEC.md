# Master Specification: MarkForge (Windows Tauri v2 + Milkdown WYSIWYG Editor)

## Objective
Build, scaffold, and verify a high-performance Windows desktop Markdown editor using **Tauri v2 (Rust)**, **React 18 (TypeScript)**, and **Milkdown Crepe (`@milkdown/crepe`)**. It must support true inline WYSIWYG editing, a multi-tab workspace, folder tree browsing, automatic screenshot pasting (`Ctrl+V`), and a 3-mode view switcher (WYSIWYG, Split View, Read-Only Lock).

---

## Phase 1: Environment Setup & Dependencies
1. Check the execution policy in PowerShell (`Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned -Force` if needed). Use `npm.cmd` if command-line scripts are restricted.
2. Initialize a Tauri v2 React-TS project in the root directory:
   `npm.cmd create tauri-app@latest . -- --template react-ts --manager npm`
3. Install project dependencies and Tauri v2 plugins:
   - `npm.cmd install`
   - `npm.cmd run tauri add dialog`
   - `npm.cmd run tauri add fs`
   - `npm.cmd install @milkdown/crepe lucide-react`
4. Ensure `src-tauri/capabilities/default.json` explicitly contains:
   - `"core:default"`
   - `"dialog:default"`
   - `"fs:default"`

---

## Phase 2: Rust Backend (`src-tauri/src/lib.rs`)
Implement and register these 4 Tauri commands in `src-tauri/src/lib.rs`:

1. **`list_markdown_files(dir_path: String) -> Result<Vec<FileEntry>, String>`**
   - Scans the directory recursively or shallowly for `.md` and `.markdown` files.
   - Returns a vector of structs with `{ name: String, path: String }`, sorted alphabetically by filename (case-insensitive).
2. **`read_markdown_file(file_path: String) -> Result<String, String>`**
   - Reads the target `.md` file from disk as UTF-8.
3. **`save_markdown_file(file_path: String, content: String) -> Result<(), String>`**
   - Writes UTF-8 text content back to disk.
4. **`save_pasted_image(active_md_path: String, image_bytes: Vec<u8>, extension: String) -> Result<String, String>`**
   - Resolves the parent directory of `active_md_path`, creates an `assets/` subfolder if it does not exist, saves the file as `img_<timestamp>.<extension>`, and returns the relative path string (`assets/img_<timestamp>.<extension>`).

Register `tauri_plugin_dialog::init()` and `tauri_plugin_fs::init()` in `tauri::Builder`.

---

## Phase 3: Frontend Editor Engine (`src/CrepeEditor.tsx`)
Create `src/CrepeEditor.tsx` wrapping `@milkdown/crepe`:
- Import styles: `@milkdown/crepe/theme/common/style.css` and `@milkdown/crepe/theme/frame-dark.css`.
- Accept props: `docId: string`, `initialContent: string`, `activeFilePath?: string`, `readOnly: boolean`, `onChange: (markdown: string) => void`.
- Configure `Crepe.Feature.ImageBlock`'s `onUpload(file: File)`:
  - If `activeFilePath` exists, convert the file to `Array.from(new Uint8Array(await file.arrayBuffer()))`, call `save_pasted_image` via Tauri `invoke`, and return the returned relative path.
  - Fallback to `URL.createObjectURL(file)` if unsaved.
- Hook into `listener.markdownUpdated` to stream updates back via `onChange`.
- Dynamically update read-only state using `crepe.setReadonly(readOnly)`.

---

## Phase 4: UI Shell & Multi-Tab Workspace (`src/App.tsx` & `src/App.css`)
Implement `src/App.tsx` and styling in `src/App.css`:
1. **Sidebar:** Folder open dialog via `@tauri-apps/plugin-dialog` (`open({ directory: true })`), populating the sidebar file list using `list_markdown_files`, plus a New File button (`Ctrl+N`).
2. **Tab Bar:** Dynamic tabs supporting multiple open notes, dirty state tracking (`*`), and tab closing.
3. **View Mode Switcher:**
   - **Inline WYSIWYG** (Default Milkdown view)
   - **Split View Toggle** (Side-by-side WYSIWYG and raw Markdown `<textarea>`)
   - **Read-Only Lock Toggle** (Locks editor state)
4. **Keyboard Shortcuts:** `Ctrl+S` (Save file / trigger native Save As dialog if new note) and `Ctrl+N` (New note).
5. **Status Bar:** Displays file path/buffer status, live word count, character count, and current mode indicator.

---

Feed this specification directly into your Antigravity agent panel to have it build and verify everything cleanly.