import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { getDocumentProxy, extractText } from 'unpdf';

// Helper to extract searchable plain text from file content (buffer)
async function extractSearchableText(type: string, mimeType: string, buffer: ArrayBuffer): Promise<string> {
  if (type === 'pdf') {
    try {
      // unpdf / pdfjs transfers and detaches the underlying ArrayBuffer.
      // We must pass a clone (buffer.slice(0)) to prevent emptying the original buffer!
      const pdf = await getDocumentProxy(new Uint8Array(buffer.slice(0)));
      const { text } = await extractText(pdf, { mergePages: true });
      return text || "";
    } catch (e: any) {
      console.error("[Search Indexer] PDF text extraction failed:", e.message);
      return "";
    }
  }

  // Handle plain text files
  const textMimeTypes = [
    'text/plain',
    'text/markdown',
    'text/html',
    'text/css',
    'text/csv',
    'application/json',
    'application/javascript',
    'application/xml',
    'text/xml'
  ];

  if (mimeType && (mimeType.startsWith('text/') || textMimeTypes.includes(mimeType))) {
    try {
      const dec = new TextDecoder();
      return dec.decode(new Uint8Array(buffer.slice(0)));
    } catch (e: any) {
      console.error("[Search Indexer] Plain text extraction failed:", e.message);
      return "";
    }
  }

  return "";
}

interface Env {
  DB: D1Database;
  BUCKET: R2Bucket;
  ASSETS: { fetch: typeof fetch };
}

const ENCRYPTION_PASSWORD = "ironmansucks";

// Derive key using SHA-256
async function getCryptoKey(): Promise<CryptoKey> {
  const enc = new TextEncoder();
  const passwordBytes = enc.encode(ENCRYPTION_PASSWORD);
  const hash = await crypto.subtle.digest("SHA-256", passwordBytes);
  
  return await crypto.subtle.importKey(
    "raw",
    hash,
    { name: "AES-GCM" },
    false,
    ["encrypt", "decrypt"]
  );
}

// Encrypt ArrayBuffer
async function encryptData(data: ArrayBuffer): Promise<ArrayBuffer> {
  const key = await getCryptoKey();
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    data
  );
  
  const combined = new Uint8Array(iv.length + ciphertext.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(ciphertext), iv.length);
  
  return combined.buffer;
}

// Decrypt ArrayBuffer
async function decryptData(data: ArrayBuffer): Promise<ArrayBuffer> {
  const key = await getCryptoKey();
  const combined = new Uint8Array(data);
  const iv = combined.subarray(0, 12);
  const ciphertext = combined.subarray(12);
  
  return await crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    key,
    ciphertext
  );
}

// Encrypt string to base64
async function encryptString(text: string): Promise<string> {
  const enc = new TextEncoder();
  const textBytes = enc.encode(text);
  const encryptedBuffer = await encryptData(textBytes.buffer);
  
  let binary = "";
  const bytes = new Uint8Array(encryptedBuffer);
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

// Decrypt base64 string to original text
async function decryptString(base64Text: string): Promise<string> {
  const binaryString = atob(base64Text);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  
  const decryptedBuffer = await decryptData(bytes.buffer);
  const dec = new TextDecoder();
  return dec.decode(decryptedBuffer);
}

const SHARE_SECRET = "keepspace-secret-sharing-key-2026";

async function generateSignature(docId: string, expires: string): Promise<string> {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(SHARE_SECRET),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const data = enc.encode(`${docId}:${expires}`);
  const signatureBuffer = await crypto.subtle.sign("HMAC", key, data);
  return Array.from(new Uint8Array(signatureBuffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

async function verifySignature(docId: string, expires: string, sig: string): Promise<boolean> {
  const expectedSig = await generateSignature(docId, expires);
  return expectedSig === sig;
}

const api = new Hono<{ Bindings: Env }>().basePath('/api');

// Enable CORS
api.use('*', cors());

// Helper: Traverse recursively upwards to build breadcrumbs
async function getBreadcrumbs(db: D1Database, folderId: string | null): Promise<{ id: string; name: string }[]> {
  const crumbs: { id: string; name: string }[] = [];
  let currentId = folderId;
  
  while (currentId) {
    const folder = await db
      .prepare("SELECT id, name, parent_id FROM folders WHERE id = ?")
      .bind(currentId)
      .first<{ id: string; name: string; parent_id: string | null }>();
      
    if (!folder) break;
    crumbs.unshift({ id: folder.id, name: folder.name });
    currentId = folder.parent_id;
  }
  return crumbs;
}

// Helper: Recursively find all documents in subfolders to delete them from R2
async function getDescendantDocuments(db: D1Database, folderId: string): Promise<{ id: string; url: string; type: string }[]> {
  const folderIds = [folderId];
  let i = 0;
  
  while (i < folderIds.length) {
    const currentId = folderIds[i];
    const subfolders = await db
      .prepare("SELECT id FROM folders WHERE parent_id = ?")
      .bind(currentId)
      .all<{ id: string }>();
      
    for (const sf of subfolders.results) {
      folderIds.push(sf.id);
    }
    i++;
  }
  
  // Find all documents inside any of these folders
  const placeholders = folderIds.map(() => "?").join(",");
  const docs = await db
    .prepare(`SELECT id, url, type FROM documents WHERE parent_id IN (${placeholders})`)
    .bind(...folderIds)
    .all<{ id: string; url: string; type: string }>();
    
  return docs.results;
}

/* ------------------- FOLDERS API ------------------- */

// Get root or folder contents
api.get('/folders', async (c) => {
  const db = c.env.DB;
  const rootFolders = await db.prepare("SELECT * FROM folders WHERE parent_id IS NULL ORDER BY name ASC").all();
  const rootDocs = await db.prepare("SELECT * FROM documents WHERE parent_id IS NULL ORDER BY created_at DESC").all();
  
  const documents = rootDocs.results as any[];
  for (const doc of documents) {
    if (doc.type === 'link') {
      try {
        doc.url = await decryptString(doc.url);
      } catch (e) {
        console.error("Link URL decryption failed: ", e);
      }
    }
  }

  return c.json({
    folder: null,
    breadcrumbs: [],
    subfolders: rootFolders.results,
    documents
  });
});

api.get('/folders/:id', async (c) => {
  const db = c.env.DB;
  const folderId = c.req.param('id');
  
  const folder = await db
    .prepare("SELECT * FROM folders WHERE id = ?")
    .bind(folderId)
    .first<{ id: string; name: string; parent_id: string | null }>();
    
  if (!folder) {
    return c.json({ error: "Folder not found" }, 404);
  }
  
  const breadcrumbs = await getBreadcrumbs(db, folderId);
  const subfolders = await db.prepare("SELECT * FROM folders WHERE parent_id = ? ORDER BY name ASC").bind(folderId).all();
  const documentsQuery = await db.prepare("SELECT * FROM documents WHERE parent_id = ? ORDER BY created_at DESC").bind(folderId).all();
  
  const documents = documentsQuery.results as any[];
  for (const doc of documents) {
    if (doc.type === 'link') {
      try {
        doc.url = await decryptString(doc.url);
      } catch (e) {
        console.error("Link URL decryption failed: ", e);
      }
    }
  }

  return c.json({
    folder,
    breadcrumbs,
    subfolders: subfolders.results,
    documents
  });
});

// Get all folders (flat list)
api.get('/all-folders', async (c) => {
  const db = c.env.DB;
  const folders = await db.prepare("SELECT * FROM folders ORDER BY name ASC").all();
  return c.json(folders.results);
});

// Create folder
api.post('/folders', async (c) => {
  const db = c.env.DB;
  const body = await c.req.json<{ name: string; parent_id: string | null }>();
  
  if (!body.name || body.name.trim() === "") {
    return c.json({ error: "Folder name is required" }, 400);
  }
  
  const id = crypto.randomUUID();
  const name = body.name.trim();
  const parentId = body.parent_id || null;
  const now = new Date().toISOString();
  
  await db
    .prepare("INSERT INTO folders (id, name, parent_id, created_at, updated_at) VALUES (?, ?, ?, ?, ?)")
    .bind(id, name, parentId, now, now)
    .run();
    
  return c.json({ id, name, parent_id: parentId, created_at: now, updated_at: now }, 201);
});

// Rename or move folder
api.put('/folders/:id', async (c) => {
  const db = c.env.DB;
  const id = c.req.param('id');
  const body = await c.req.json<{ name?: string; parent_id?: string | null }>();
  
  const folder = await db.prepare("SELECT id FROM folders WHERE id = ?").bind(id).first();
  if (!folder) {
    return c.json({ error: "Folder not found" }, 404);
  }
  
  const now = new Date().toISOString();
  
  // Avoid cyclic hierarchy loop: don't move a folder into its own children or itself
  if (body.parent_id !== undefined) {
    if (body.parent_id === id) {
      return c.json({ error: "Cannot move a folder into itself" }, 400);
    }
    let checkParentId = body.parent_id;
    while (checkParentId !== null) {
      const parent = await db.prepare("SELECT parent_id FROM folders WHERE id = ?").bind(checkParentId).first<{ parent_id: string | null }>();
      if (!parent) break;
      if (parent.parent_id === id) {
        return c.json({ error: "Cannot move a folder inside one of its subfolders (hierarchy loop)" }, 400);
      }
      checkParentId = parent.parent_id;
    }
  }

  if (body.name !== undefined && body.parent_id !== undefined) {
    await db
      .prepare("UPDATE folders SET name = ?, parent_id = ?, updated_at = ? WHERE id = ?")
      .bind(body.name.trim(), body.parent_id, now, id)
      .run();
  } else if (body.name !== undefined) {
    await db
      .prepare("UPDATE folders SET name = ?, updated_at = ? WHERE id = ?")
      .bind(body.name.trim(), now, id)
      .run();
  } else if (body.parent_id !== undefined) {
    await db
      .prepare("UPDATE folders SET parent_id = ?, updated_at = ? WHERE id = ?")
      .bind(body.parent_id, now, id)
      .run();
  }
  
  const updated = await db.prepare("SELECT * FROM folders WHERE id = ?").bind(id).first();
  return c.json(updated);
});

// Delete folder (cascading files inside database & R2)
api.delete('/folders/:id', async (c) => {
  const db = c.env.DB;
  const bucket = c.env.BUCKET;
  const id = c.req.param('id');
  
  const folder = await db.prepare("SELECT id FROM folders WHERE id = ?").bind(id).first();
  if (!folder) {
    return c.json({ error: "Folder not found" }, 404);
  }
  
  // 1. Gather all documents under this folder recursively
  const descendants = await getDescendantDocuments(db, id);
  
  // 2. Delete all non-link file objects from R2
  const r2DeletePromises = descendants
    .filter(doc => doc.type !== 'link')
    .map(doc => bucket.delete(doc.url));
  await Promise.all(r2DeletePromises);
  
  // 3. Delete root folder and rely on cascading deletes inside DB (or delete explicitly)
  // Let's delete documents under subfolders manually to be safe, then folders
  const folderIds = [id];
  let i = 0;
  while (i < folderIds.length) {
    const currentId = folderIds[i];
    const subfolders = await db.prepare("SELECT id FROM folders WHERE parent_id = ?").bind(currentId).all<{ id: string }>();
    for (const sf of subfolders.results) {
      folderIds.push(sf.id);
    }
    i++;
  }
  
  // Delete all descendants documents from DB
  const placeholders = folderIds.map(() => "?").join(",");
  await db.prepare(`DELETE FROM documents WHERE parent_id IN (${placeholders}) OR parent_id = ?`).bind(...folderIds, id).run();
  
  // Delete all subfolders and folder itself
  await db.prepare(`DELETE FROM folders WHERE id IN (${placeholders}) OR id = ?`).bind(...folderIds, id).run();
  
  return c.json({ success: true, deletedFolderId: id });
});

/* ------------------- DOCUMENTS API ------------------- */

// Get document details
api.get('/documents/:id', async (c) => {
  const db = c.env.DB;
  const docId = c.req.param('id');
  const doc = await db.prepare("SELECT * FROM documents WHERE id = ?").bind(docId).first<any>();
  if (!doc) {
    return c.json({ error: "Document not found" }, 404);
  }
  if (doc.type === 'link') {
    try {
      doc.url = await decryptString(doc.url);
    } catch (e) {
      console.error("Failed to decrypt link details url: ", e);
    }
  }
  return c.json(doc);
});

// Upload document (file multipart or link save)
api.post('/documents', async (c) => {
  const db = c.env.DB;
  const bucket = c.env.BUCKET;
  
  const contentType = c.req.header('content-type') || '';
  const now = new Date().toISOString();
  
  if (contentType.includes('multipart/form-data')) {
    const formData = await c.req.formData();
    const file = formData.get('file') as File;
    const parentId = (formData.get('parent_id') as string) || null;
    const description = (formData.get('description') as string) || '';
    
    if (!file) {
      return c.json({ error: "No file provided" }, 400);
    }
    
    const docId = crypto.randomUUID();
    const name = file.name;
    let mimeType = file.type || '';
    const size = file.size;
    const r2Key = `files/${docId}_${encodeURIComponent(name)}`;
    
    // Determine category type with robust file extension fallbacks (critical for mobile uploads)
    const lowerName = name.toLowerCase();
    let type = 'other';
    if (mimeType.startsWith('image/') || /\.(jpe?g|png|gif|webp|svg|bmp|heic|heif)$/i.test(lowerName)) {
      type = 'image';
      if (!mimeType || mimeType === 'application/octet-stream') {
        mimeType = lowerName.endsWith('.png') ? 'image/png' : 'image/jpeg';
      }
    } else if (mimeType.startsWith('video/') || /\.(mp4|mov|webm|mkv|avi|m4v)$/i.test(lowerName)) {
      type = 'video';
      if (!mimeType || mimeType === 'application/octet-stream') {
        mimeType = 'video/mp4';
      }
    } else if (mimeType === 'application/pdf' || lowerName.endsWith('.pdf')) {
      type = 'pdf';
      mimeType = 'application/pdf';
    } else if (/\.(txt|md|csv|json|xml|html|css|js|ts)$/i.test(lowerName)) {
      if (!mimeType || mimeType === 'application/octet-stream') {
        mimeType = 'text/plain';
      }
    }
    
    let fileBuffer: ArrayBuffer;
    try {
      fileBuffer = await file.arrayBuffer();
    } catch (e: any) {
      console.error("Failed to read file arrayBuffer: ", e.message);
      return c.json({ error: "Failed to read file data" }, 400);
    }
    
    let fileData: ArrayBuffer = fileBuffer;
    let extractedText: string | null = null;
    
    // Encrypt PDFs, Photos, and other formats (skip videos)
    if (type !== 'video') {
      try {
        // Extract searchable text from a cloned copy of unencrypted buffer in memory
        try {
          extractedText = await extractSearchableText(type, mimeType, fileBuffer.slice(0));
        } catch (e: any) {
          console.error("Text extraction failed during upload: ", e.message);
        }

        // Safeguard: Ensure buffer was not detached; re-read if byteLength was emptied
        if (fileBuffer.byteLength === 0 && size > 0) {
          console.warn("[Upload Guard] fileBuffer was detached! Re-reading from file stream...");
          fileBuffer = await file.arrayBuffer();
        }

        fileData = await encryptData(fileBuffer);
      } catch (e) {
        console.error("Encryption error during upload: ", e);
        return c.json({ error: "File encryption failed" }, 500);
      }
    }
    
    // Store in R2 (either raw stream for videos or encrypted buffer)
    await bucket.put(r2Key, fileData, {
      httpMetadata: { contentType: mimeType }
    });
    
    // Save metadata in D1
    await db
      .prepare("INSERT INTO documents (id, name, type, mime_type, size, url, parent_id, description, favorite, extracted_text, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?)")
      .bind(docId, name, type, mimeType, size, r2Key, parentId, description, extractedText, now, now)
      .run();
      
    const inserted = await db.prepare("SELECT * FROM documents WHERE id = ?").bind(docId).first();
    return c.json(inserted, 201);
  } else {
    // Treat as JSON Link creation
    const body = await c.req.json<{ url: string; parent_id?: string | null; description?: string }>();
    if (!body.url) {
      return c.json({ error: "URL is required" }, 400);
    }
    
    const docId = crypto.randomUUID();
    let name = body.url.replace(/^https?:\/\/(www\.)?/, '');
    if (name.length > 50) name = name.substring(0, 47) + '...';
    
    let description = body.description || '';
    let thumbnail_url = '';
    const parentId = body.parent_id || null;
    
    // Premium link parsing inside worker using HTMLRewriter
    try {
      const linkRes = await fetch(body.url, {
        headers: { 'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' },
        signal: AbortSignal.timeout(5000)
      });
      
      if (linkRes.ok) {
        const bodyText = await linkRes.text();
        let titleVal = '';
        let descVal = '';
        let imageVal = '';
        
        const rewriteRes = new Response(bodyText);
        const rewriter = new HTMLRewriter()
          .on('title', {
            text(text) { titleVal += text.text; }
          })
          .on('meta[name="description"]', {
            element(el) { descVal = el.getAttribute('content') || descVal; }
          })
          .on('meta[property="og:description"]', {
            element(el) { descVal = el.getAttribute('content') || descVal; }
          })
          .on('meta[property="og:title"]', {
            element(el) { titleVal = el.getAttribute('content') || titleVal; }
          })
          .on('meta[property="og:image"]', {
            element(el) { imageVal = el.getAttribute('content') || imageVal; }
          });
          
        await rewriter.transform(rewriteRes).text();
        
        if (titleVal.trim()) name = titleVal.trim();
        if (descVal.trim()) description = descVal.trim();
        if (imageVal.trim()) thumbnail_url = imageVal.trim();
      }
    } catch (e) {
      // Fail-silent, just use default hostname as title and empty description
      console.error("Link metadata parsing failed: ", e);
    }
    
    // Encrypt the link URL before saving in database
    let encryptedUrl = body.url;
    try {
      encryptedUrl = await encryptString(body.url);
    } catch (e) {
      return c.json({ error: "Link encryption failed" }, 500);
    }
    
    await db
      .prepare("INSERT INTO documents (id, name, type, mime_type, size, url, parent_id, description, favorite, thumbnail_url, created_at, updated_at) VALUES (?, ?, ?, ?, NULL, ?, ?, ?, 0, ?, ?, ?)")
      .bind(docId, name, 'link', 'text/html', encryptedUrl, parentId, description, thumbnail_url, now, now)
      .run();
      
    const inserted = await db.prepare("SELECT * FROM documents WHERE id = ?").bind(docId).first<any>();
    if (inserted && inserted.type === 'link') {
      try {
        inserted.url = await decryptString(inserted.url);
      } catch (e) {
        console.error("Failed to decrypt newly inserted link: ", e);
      }
    }
    return c.json(inserted, 201);
  }
});

// Update document details (rename, toggle favorite, edit description, move)
api.put('/documents/:id', async (c) => {
  const db = c.env.DB;
  const id = c.req.param('id');
  const body = await c.req.json<{ name?: string; parent_id?: string | null; favorite?: number; description?: string }>();
  
  const doc = await db.prepare("SELECT id FROM documents WHERE id = ?").bind(id).first();
  if (!doc) {
    return c.json({ error: "Document not found" }, 404);
  }
  
  const now = new Date().toISOString();
  
  // Dynamically build update query
  const fields: string[] = [];
  const bindings: any[] = [];
  
  if (body.name !== undefined) {
    fields.push("name = ?");
    bindings.push(body.name.trim());
  }
  if (body.parent_id !== undefined) {
    fields.push("parent_id = ?");
    bindings.push(body.parent_id);
  }
  if (body.favorite !== undefined) {
    fields.push("favorite = ?");
    bindings.push(body.favorite);
  }
  if (body.description !== undefined) {
    fields.push("description = ?");
    bindings.push(body.description);
  }
  
  if (fields.length === 0) {
    return c.json({ error: "No fields to update" }, 400);
  }
  
  fields.push("updated_at = ?");
  bindings.push(now);
  bindings.push(id);
  
  const query = `UPDATE documents SET ${fields.join(", ")} WHERE id = ?`;
  await db.prepare(query).bind(...bindings).run();
  
  const updated = await db.prepare("SELECT * FROM documents WHERE id = ?").bind(id).first();
  return c.json(updated);
});

// Delete document from D1 & R2
api.delete('/documents/:id', async (c) => {
  const db = c.env.DB;
  const bucket = c.env.BUCKET;
  const id = c.req.param('id');
  
  const doc = await db.prepare("SELECT id, type, url FROM documents WHERE id = ?").bind(id).first<{ id: string; type: string; url: string }>();
  if (!doc) {
    return c.json({ error: "Document not found" }, 404);
  }
  
  // Delete from R2 object storage if it's not a link
  if (doc.type !== 'link') {
    try {
      await bucket.delete(doc.url);
    } catch (e) {
      console.error("R2 deletion failed: ", e);
    }
  }
  
  // Delete metadata record from D1
  await db.prepare("DELETE FROM documents WHERE id = ?").bind(id).run();
  return c.json({ success: true, deletedDocId: id });
});

// Download/Stream document file from R2
api.get('/documents/:id/download', async (c) => {
  const db = c.env.DB;
  const bucket = c.env.BUCKET;
  const id = c.req.param('id');
  
  const doc = await db.prepare("SELECT * FROM documents WHERE id = ?").bind(id).first<{ type: string; url: string; name: string; mime_type: string }>();
  if (!doc) {
    return c.json({ error: "Document not found" }, 404);
  }
  
  if (doc.type === 'link') {
    try {
      const decryptedUrl = await decryptString(doc.url);
      return c.redirect(decryptedUrl);
    } catch (e) {
      return c.json({ error: "Link decryption failed" }, 500);
    }
  }
  
  const object = await bucket.get(doc.url);
  if (!object) {
    return c.json({ error: "File not found in object storage" }, 404);
  }
  
  const headers = new Headers();
  object.writeHttpMetadata(headers);
  headers.set('etag', object.httpEtag);
  
  // Inline/Attachment content disposition with RFC 6266 filename parameter
  const isDownload = c.req.query('download') === 'true';
  const safeAsciiName = doc.name.replace(/[^a-zA-Z0-9._-]/g, '_');
  const encodedName = encodeURIComponent(doc.name);
  headers.set(
    'Content-Disposition',
    `${isDownload ? 'attachment' : 'inline'}; filename="${safeAsciiName}"; filename*=UTF-8''${encodedName}`
  );
  headers.set('Content-Type', doc.mime_type || 'application/octet-stream');
  
  let finalBody: ArrayBuffer | ReadableStream = object.body;
  
  // Decrypt photos, PDFs, and other encrypted categories (skip videos)
  if (doc.type !== 'video') {
    try {
      const encryptedBuffer = await object.arrayBuffer();
      finalBody = await decryptData(encryptedBuffer);
      
      headers.set('Content-Length', finalBody.byteLength.toString());
      headers.delete('content-encoding');
    } catch (e) {
      console.error("Decryption error during download: ", e);
      return c.json({ error: "File decryption failed" }, 500);
    }
  }
  
  return new Response(finalBody, { headers });
});

// Generate Temporary Share Link
api.post('/documents/:id/share', async (c) => {
  const db = c.env.DB;
  const id = c.req.param('id');
  const body = await c.req.json<{ expires_in: number | null }>();
  
  const doc = await db.prepare("SELECT id FROM documents WHERE id = ?").bind(id).first();
  if (!doc) {
    return c.json({ error: "Document not found" }, 404);
  }
  
  const expires = body.expires_in 
    ? (Date.now() + body.expires_in * 1000).toString() 
    : "forever";
    
  const signature = await generateSignature(id, expires);
  const requestUrl = new URL(c.req.url);
  const baseUrl = `${requestUrl.protocol}//${requestUrl.host}`;
  const shareUrl = `${baseUrl}/api/public/documents/${id}?expires=${expires}&sig=${signature}`;
  
  return c.json({ shareUrl });
});

// View Public Shared Document file (bypasses app login)
api.get('/public/documents/:id', async (c) => {
  const db = c.env.DB;
  const bucket = c.env.BUCKET;
  const id = c.req.param('id');
  const expires = c.req.query('expires') || '';
  const sig = c.req.query('sig') || '';
  
  if (!expires || !sig) {
    return c.text("Unauthorized: missing parameters", 401);
  }
  
  const isValid = await verifySignature(id, expires, sig);
  if (!isValid) {
    return c.text("Unauthorized: invalid signature hash", 401);
  }
  
  if (expires !== 'forever') {
    const expiryTime = parseInt(expires, 10);
    if (isNaN(expiryTime) || Date.now() > expiryTime) {
      return c.text("Unauthorized: sharing link has expired", 410);
    }
  }
  
  const doc = await db.prepare("SELECT * FROM documents WHERE id = ?").bind(id).first<{ type: string; url: string; name: string; mime_type: string }>();
  if (!doc) {
    return c.text("Document not found", 404);
  }
  
  if (doc.type === 'link') {
    try {
      const decryptedUrl = await decryptString(doc.url);
      return c.redirect(decryptedUrl);
    } catch (e) {
      return c.text("Decryption failed", 500);
    }
  }
  
  const object = await bucket.get(doc.url);
  if (!object) {
    return c.text("File not found in object storage", 404);
  }
  
  const headers = new Headers();
  object.writeHttpMetadata(headers);
  headers.set('etag', object.httpEtag);
  
  const isDownload = c.req.query('download') === 'true';
  const safeAsciiName = doc.name.replace(/[^a-zA-Z0-9._-]/g, '_');
  const encodedName = encodeURIComponent(doc.name);
  headers.set(
    'Content-Disposition',
    `${isDownload ? 'attachment' : 'inline'}; filename="${safeAsciiName}"; filename*=UTF-8''${encodedName}`
  );
  headers.set('Content-Type', doc.mime_type || 'application/octet-stream');
  
  let finalBody: ArrayBuffer | ReadableStream = object.body;
  
  if (doc.type !== 'video') {
    try {
      const encryptedBuffer = await object.arrayBuffer();
      finalBody = await decryptData(encryptedBuffer);
      headers.set('Content-Length', finalBody.byteLength.toString());
      headers.delete('content-encoding');
    } catch (e) {
      return c.text("Decryption failed", 500);
    }
  }
  
  return new Response(finalBody, { headers });
});

/* ------------------- GLOBAL SEARCH & STATS ------------------- */

api.get('/search', async (c) => {
  const db = c.env.DB;
  const query = c.req.query('q') || '';
  
  if (!query.trim()) {
    return c.json({ folders: [], documents: [] });
  }
  
  const likePattern = `%${query.trim()}%`;
  
  const matchedFolders = await db
    .prepare("SELECT * FROM folders WHERE name LIKE ? ORDER BY name ASC")
    .bind(likePattern)
    .all();
    
  const matchedDocsQuery = await db
    .prepare("SELECT * FROM documents WHERE name LIKE ? OR description LIKE ? OR extracted_text LIKE ? ORDER BY created_at DESC")
    .bind(likePattern, likePattern, likePattern)
    .all();
    
  const documents = matchedDocsQuery.results as any[];
  for (const doc of documents) {
    if (doc.type === 'link') {
      try {
        doc.url = await decryptString(doc.url);
      } catch (e) {
        console.error("Failed to decrypt search doc: ", e);
      }
    }
  }

  return c.json({
    folders: matchedFolders.results,
    documents
  });
});

api.get('/stats', async (c) => {
  const db = c.env.DB;
  
  const foldersCount = await db.prepare("SELECT COUNT(*) as count FROM folders").first<{ count: number }>();
  const totalCount = await db.prepare("SELECT COUNT(*) as count FROM documents").first<{ count: number }>();
  const typeStats = await db.prepare("SELECT type, COUNT(*) as count, SUM(size) as total_size FROM documents GROUP BY type").all<{ type: string; count: number; total_size: number | null }>();
  
  return c.json({
    foldersCount: foldersCount?.count || 0,
    totalCount: totalCount?.count || 0,
    byType: typeStats.results
  });
});

/* ------------------- WORKER ROOT ROUTING FALLBACK ------------------- */

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    
    // API endpoint routing -> Hono api router
    if (url.pathname.startsWith('/api')) {
      return api.fetch(request, env, ctx);
    }
    
    // Otherwise fallback to ASSETS static web server
    try {
      let response = await env.ASSETS.fetch(request);
      
      // If index or specific asset is missing (like client routed paths), serve index.html
      if (response.status === 404) {
        const indexUrl = new URL('/index.html', request.url);
        const indexRequest = new Request(indexUrl.toString(), request);
        response = await env.ASSETS.fetch(indexRequest);
      }
      
      return response;
    } catch (e) {
      return new Response("Asset not found (ASSETS binding not available)", { status: 404 });
    }
  }
};
