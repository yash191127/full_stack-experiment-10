

const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const EventEmitter = require('events');

const app = express();
const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/blog';
const JWT_SECRET = process.env.JWT_SECRET || 'devsecret';

app.use(cors());
app.use(bodyParser.json());

// ----- MongoDB / Mongoose setup -----
mongoose.set('strictQuery', false);
mongoose.connect(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => {
    console.error('MongoDB connection error:', err.message);
    process.exit(1);
  });

// ----- Schemas -----
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  passwordHash: { type: String, required: true },
  displayName: { type: String }
});
const User = mongoose.model('User', userSchema);

const postSchema = new mongoose.Schema({
  title: { type: String, required: true },
  body: { type: String, required: true },
  author: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  createdAt: { type: Date, default: Date.now }
});
const Post = mongoose.model('Post', postSchema);

const commentSchema = new mongoose.Schema({
  post: { type: mongoose.Schema.Types.ObjectId, ref: 'Post', required: true },
  author: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  text: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});
const Comment = mongoose.model('Comment', commentSchema);

// ----- Simple in-memory event emitter for SSE (per-post channels) -----
const sseEmitter = new EventEmitter();
// prevent memory leak warnings for many listeners
sseEmitter.setMaxListeners(1000);

// ----- Auth helpers -----
function generateToken(user){
  return jwt.sign({ id: user._id, username: user.username, displayName: user.displayName }, JWT_SECRET, { expiresIn: '7d' });
}

async function authMiddleware(req, res, next){
  const auth = req.headers.authorization;
  if(!auth) return res.status(401).json({ error: 'No authorization header' });
  const parts = auth.split(' ');
  if(parts.length !== 2 || parts[0] !== 'Bearer') return res.status(401).json({ error: 'Invalid authorization format' });
  const token = parts[1];
  try{
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = await User.findById(payload.id).select('-passwordHash');
    if(!req.user) return res.status(401).json({ error: 'User not found' });
    next();
  }catch(err){
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// ----- Routes: Auth -----
app.post('/api/auth/register', async (req, res) => {
  try{
    const { username, password, displayName } = req.body;
    if(!username || !password) return res.status(400).json({ error: 'username and password required' });
    const existing = await User.findOne({ username });
    if(existing) return res.status(400).json({ error: 'username already taken' });
    const salt = await bcrypt.genSalt(10);
    const hash = await bcrypt.hash(password, salt);
    const user = new User({ username, passwordHash: hash, displayName: displayName || username });
    await user.save();
    const token = generateToken(user);
    res.json({ token, user: { id: user._id, username: user.username, displayName: user.displayName } });
  }catch(err){
    console.error(err);
    res.status(500).json({ error: 'registration failed' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try{
    const { username, password } = req.body;
    if(!username || !password) return res.status(400).json({ error: 'username and password required' });
    const user = await User.findOne({ username });
    if(!user) return res.status(400).json({ error: 'invalid credentials' });
    const ok = await bcrypt.compare(password, user.passwordHash);
    if(!ok) return res.status(400).json({ error: 'invalid credentials' });
    const token = generateToken(user);
    res.json({ token, user: { id: user._id, username: user.username, displayName: user.displayName } });
  }catch(err){
    console.error(err);
    res.status(500).json({ error: 'login failed' });
  }
});

// ----- Routes: Users -----
app.get('/api/me', authMiddleware, async (req, res) => {
  res.json({ user: { id: req.user._id, username: req.user.username, displayName: req.user.displayName } });
});

// ----- Routes: Posts -----
app.get('/api/posts', async (req, res) => {
  try{
    const posts = await Post.find().sort({ createdAt: -1 }).populate('author', 'username displayName');
    res.json(posts);
  }catch(err){
    console.error(err);
    res.status(500).json({ error: 'failed to fetch posts' });
  }
});

app.post('/api/posts', authMiddleware, async (req, res) => {
  try{
    const { title, body } = req.body;
    if(!title || !body) return res.status(400).json({ error: 'title and body required' });
    const post = new Post({ title, body, author: req.user._id });
    await post.save();
    const populated = await Post.findById(post._id).populate('author', 'username displayName');
    res.status(201).json(populated);
  }catch(err){
    console.error(err);
    res.status(500).json({ error: 'failed to create post' });
  }
});

app.put('/api/posts/:id', authMiddleware, async (req, res) => {
  try{
    const { id } = req.params;
    const post = await Post.findById(id);
    if(!post) return res.status(404).json({ error: 'post not found' });
    if(!post.author.equals(req.user._id)) return res.status(403).json({ error: 'not authorized' });
    const { title, body } = req.body;
    if(title) post.title = title;
    if(body) post.body = body;
    await post.save();
    const populated = await Post.findById(post._id).populate('author', 'username displayName');
    res.json(populated);
  }catch(err){
    console.error(err);
    res.status(500).json({ error: 'failed to update post' });
  }
});

app.delete('/api/posts/:id', authMiddleware, async (req, res) => {
  try{
    const { id } = req.params;
    const post = await Post.findById(id);
    if(!post) return res.status(404).json({ error: 'post not found' });
    if(!post.author.equals(req.user._id)) return res.status(403).json({ error: 'not authorized' });
    await Comment.deleteMany({ post: post._id }); // remove related comments
    await post.deleteOne();
    res.json({ success: true });
  }catch(err){
    console.error(err);
    res.status(500).json({ error: 'failed to delete post' });
  }
});

// ----- Routes: Comments -----
app.get('/api/posts/:postId/comments', async (req, res) => {
  try{
    const { postId } = req.params;
    const comments = await Comment.find({ post: postId }).sort({ createdAt: 1 }).populate('author', 'username displayName');
    res.json(comments);
  }catch(err){
    console.error(err);
    res.status(500).json({ error: 'failed to fetch comments' });
  }
});

app.post('/api/posts/:postId/comments', authMiddleware, async (req, res) => {
  try{
    const { postId } = req.params;
    const { text } = req.body;
    if(!text) return res.status(400).json({ error: 'text required' });
    const post = await Post.findById(postId);
    if(!post) return res.status(404).json({ error: 'post not found' });
    const comment = new Comment({ post: post._id, author: req.user._id, text });
    await comment.save();
    const populated = await Comment.findById(comment._id).populate('author', 'username displayName');

    // emit SSE event for this post
    sseEmitter.emit(`comments:${postId}`, populated);

    res.status(201).json(populated);
  }catch(err){
    console.error(err);
    res.status(500).json({ error: 'failed to add comment' });
  }
});

// SSE endpoint: client connects and server pushes new comments for a post
app.get('/api/posts/:postId/comments/stream', (req, res) => {
  const { postId } = req.params;
  // set headers for SSE
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders && res.flushHeaders();

  const onComment = (comment) => {
    res.write(`data: ${JSON.stringify(comment)}\n\n`);
  };

  sseEmitter.on(`comments:${postId}`, onComment);

  // send a comment every 25s ping to keep connection alive (optional)
  const keepAlive = setInterval(() => {
    res.write(`:\n`);
  }, 25000);

  // clean up when client disconnects
  req.on('close', () => {
    clearInterval(keepAlive);
    sseEmitter.removeListener(`comments:${postId}`, onComment);
  });
});

// Simple health
app.get('/api/health', (req, res) => res.json({ ok: true }));

// ----- Frontend: React SPA via CDN -----
app.get('/', (req, res) => {
  res.send(`<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Blog Platform - Single File</title>
    <style>
      body { font-family: Arial, sans-serif; margin:0; padding:0; background:#f5f6f8; }
      .container { max-width:960px; margin:32px auto; background:white; padding:20px; border-radius:8px; box-shadow:0 8px 24px rgba(0,0,0,0.06); }
      header { display:flex; justify-content:space-between; align-items:center; margin-bottom:12px; }
      h1 { margin:0; }
      .flex { display:flex; gap:8px; align-items:center; }
      .post { border-bottom:1px solid #eee; padding:12px 0; }
      .post h3 { margin:0 0 6px 0; }
      .meta { font-size:13px; color:#666; }
      .btn { padding:6px 10px; border-radius:6px; border:none; cursor:pointer; }
      .btn.primary { background:#2563eb; color:white; }
      .btn.ghost { background:transparent; border:1px solid #ddd; }
      .form-row { margin-bottom:8px; }
      textarea { width:100%; min-height:100px; }
      input[type=text], textarea { padding:8px; border-radius:6px; border:1px solid #ddd; }
      .comments { margin-top:8px; padding-left:12px; }
      .comment { margin-bottom:8px; }
      .small { font-size:13px; color:#666 }
    </style>
  </head>
  <body>
    <div id="root" class="container"></div>

    <script src="https://unpkg.com/react@18/umd/react.development.js" crossorigin></script>
    <script src="https://unpkg.com/react-dom@18/umd/react-dom.development.js" crossorigin></script>
    <script src="https://unpkg.com/babel-standalone@6.26.0/babel.min.js"></script>

    <script type="text/babel">
      const { useState, useEffect, useRef } = React;

      // Simple helper to call API with optional auth
      function api(path, method='GET', body=null, token=null){
        const opts = { method, headers: {} };
        if(body) { opts.headers['Content-Type'] = 'application/json'; opts.body = JSON.stringify(body); }
        if(token) opts.headers['Authorization'] = 'Bearer '+token;
        return fetch(path, opts).then(r => r.json());
      }

      function App(){
        const [token, setToken] = useState(localStorage.getItem('token'));
        const [me, setMe] = useState(null);
        const [posts, setPosts] = useState([]);
        const [loading, setLoading] = useState(false);

        useEffect(()=>{ loadPosts(); if(token) loadMe(); }, [token]);

        async function loadMe(){
          const res = await api('/api/me', 'GET', null, token);
          if(res.user) setMe(res.user);
          else { setToken(null); localStorage.removeItem('token'); }
        }

        async function loadPosts(){
          setLoading(true);
          const data = await api('/api/posts');
          setPosts(data || []);
          setLoading(false);
        }

        function onLogin(token, user){
          setToken(token); localStorage.setItem('token', token); setMe(user);
        }
        function onLogout(){ setToken(null); localStorage.removeItem('token'); setMe(null); }

        return (
          <div>
            <header>
              <h1>Mini Blog</h1>
              <div className="flex">
                {me ? (
                  <>
                    <div className="small">Signed in as <strong>{me.displayName}</strong></div>
                    <button className="btn ghost" onClick={onLogout}>Logout</button>
                  </>
                ) : (
                  <AuthForms onLogin={onLogin} />
                )}
              </div>
            </header>

            <CreatePost token={token} onCreated={(p)=>setPosts(prev=>[p,...prev])} />

            {loading ? <p className="small">Loading posts...</p> : null}

            <div>
              {posts.map(post => (
                <PostCard key={post._id} post={post} token={token} currentUser={me} onUpdated={(u)=>setPosts(prev=>prev.map(p=>p._id===u._id?u:p))} onDeleted={(id)=>setPosts(prev=>prev.filter(p=>p._id!==id))} />
              ))}
            </div>
          </div>
        );
      }

      function AuthForms({ onLogin }){
        const [mode, setMode] = useState('login');
        const [username, setUsername] = useState('');
        const [password, setPassword] = useState('');
        const [displayName, setDisplayName] = useState('');
        const [err, setErr] = useState(null);

        async function submit(e){
          e.preventDefault(); setErr(null);
          try{
            const path = mode === 'login' ? '/api/auth/login' : '/api/auth/register';
            const body = mode === 'login' ? { username, password } : { username, password, displayName };
            const res = await api(path, 'POST', body);
            if(res.error) return setErr(res.error);
            onLogin(res.token, res.user);
            setUsername(''); setPassword(''); setDisplayName('');
          }catch(e){ setErr('request failed'); }
        }

        return (
          <form onSubmit={submit} style={{display:'flex', gap:8, alignItems:'center'}}>
            {mode === 'register' && <input placeholder="Display name" value={displayName} onChange={e=>setDisplayName(e.target.value)} />}
            <input placeholder="Username" value={username} onChange={e=>setUsername(e.target.value)} />
            <input placeholder="Password" type="password" value={password} onChange={e=>setPassword(e.target.value)} />
            <button className="btn primary" type="submit">{mode==='login'?'Login':'Register'}</button>
            <button type="button" className="btn ghost" onClick={()=>setMode(mode==='login'?'register':'login')}>{mode==='login'?'Switch to Register':'Switch to Login'}</button>
            {err && <div style={{color:'red'}}>{err}</div>}
          </form>
        );
      }

      function CreatePost({ token, onCreated }){
        const [title, setTitle] = useState('');
        const [body, setBody] = useState('');
        async function submit(e){
          e.preventDefault();
          if(!token) return alert('Login to create posts');
          const res = await api('/api/posts', 'POST', { title, body }, token);
          if(res.error) return alert(res.error);
          onCreated(res);
          setTitle(''); setBody('');
        }
        return (
          <form onSubmit={submit} style={{marginBottom:12}}>
            <div className="form-row"><input type="text" placeholder="Post title" value={title} onChange={e=>setTitle(e.target.value)} /></div>
            <div className="form-row"><textarea placeholder="Write your post..." value={body} onChange={e=>setBody(e.target.value)} /></div>
            <div className="form-row"><button className="btn primary" type="submit">Publish</button></div>
          </form>
        );
      }

      function PostCard({ post, token, currentUser, onUpdated, onDeleted }){
        const [showComments, setShowComments] = useState(false);
        const [comments, setComments] = useState([]);
        const sseRef = useRef(null);

        async function loadComments(){
          const res = await api(`/api/posts/${post._id}/comments`);
          setComments(res || []);
        }

        useEffect(()=>{
          if(showComments){
            loadComments();
            // connect to SSE
            const es = new EventSource(`/api/posts/${post._id}/comments/stream`);
            sseRef.current = es;
            es.onmessage = (evt)=>{
              try{ const comment = JSON.parse(evt.data); setComments(prev=>[...prev, comment]); }catch(e){}
            };
            es.onerror = ()=>{ es.close(); };
            return ()=>{ es.close(); };
          }
        }, [showComments]);

        async function remove(){ if(!confirm('Delete post?')) return; const res = await api(`/api/posts/${post._id}`, 'DELETE', null, token); if(res.error) return alert(res.error); onDeleted(post._id); }

        async function edit(){
          const newTitle = prompt('New title', post.title); if(newTitle===null) return;
          const newBody = prompt('New body', post.body); if(newBody===null) return;
          const res = await api(`/api/posts/${post._id}`, 'PUT', { title: newTitle, body: newBody }, token);
          if(res.error) return alert(res.error);
          onUpdated(res);
        }

        return (
          <div className="post">
            <h3>{post.title}</h3>
            <div className="meta">by <strong>{post.author.displayName || post.author.username}</strong> • <span className="small">{new Date(post.createdAt).toLocaleString()}</span></div>
            <p>{post.body}</p>
            <div className="flex">
              <button className="btn ghost" onClick={()=>setShowComments(s=>!s)}>{showComments? 'Hide Comments':'Show Comments'}</button>
              {currentUser && post.author && currentUser.id === post.author._id && (
                <>
                  <button className="btn" onClick={edit}>Edit</button>
                  <button className="btn" onClick={remove}>Delete</button>
                </>
              )}
            </div>

            {showComments && (
              <div className="comments">
                <CommentForm postId={post._id} token={token} onAdded={(c)=>setComments(prev=>[...prev, c])} />
                <div>
                  {comments.map(c=> (
                    <div className="comment" key={c._id}><strong>{c.author.displayName || c.author.username}</strong>: {c.text} <div className="small">{new Date(c.createdAt).toLocaleString()}</div></div>
                  ))}
                </div>
              </div>
            )}
          </div>
        );
      }

      function CommentForm({ postId, token, onAdded }){
        const [text, setText] = useState('');
        async function submit(e){
          e.preventDefault();
          if(!token) return alert('Login to comment');
          const res = await api(`/api/posts/${postId}/comments`, 'POST', { text }, token);
          if(res.error) return alert(res.error);
          setText('');
          onAdded(res);
        }
        return (
          <form onSubmit={submit} style={{marginBottom:8}}>
            <input type="text" placeholder="Write a comment..." value={text} onChange={e=>setText(e.target.value)} />
            <button className="btn" type="submit">Comment</button>
          </form>
        );
      }

      ReactDOM.createRoot(document.getElementById('root')).render(<App />);
    </script>
  </body>
</html>`);
});

// ----- Start server -----
app.listen(PORT, () => {
  console.log(`Server listening on http://localhost:${PORT}`);
});
