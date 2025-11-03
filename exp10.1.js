
const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/todos';

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

const todoSchema = new mongoose.Schema({
  text: { type: String, required: true },
  completed: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});

const Todo = mongoose.model('Todo', todoSchema);

// ----- API routes -----
app.get('/api/todos', async (req, res) => {
  try {
    const todos = await Todo.find().sort({ createdAt: -1 });
    res.json(todos);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch todos' });
  }
});

app.post('/api/todos', async (req, res) => {
  try {
    const { text } = req.body;
    if (!text || !text.trim()) return res.status(400).json({ error: 'Text is required' });
    const todo = new Todo({ text: text.trim() });
    await todo.save();
    res.status(201).json(todo);
  } catch (err) {
    res.status(500).json({ error: 'Failed to create todo' });
  }
});

app.put('/api/todos/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const payload = req.body; // { text?, completed? }
    const todo = await Todo.findByIdAndUpdate(id, payload, { new: true });
    if (!todo) return res.status(404).json({ error: 'Todo not found' });
    res.json(todo);
  } catch (err) {
    res.status(500).json({ error: 'Failed to update todo' });
  }
});

app.delete('/api/todos/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const todo = await Todo.findByIdAndDelete(id);
    if (!todo) return res.status(404).json({ error: 'Todo not found' });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete todo' });
  }
});

// Simple health check
app.get('/api/health', (req, res) => res.json({ ok: true }));

// ----- Frontend: serve a single-page React app (via CDN) -----
app.get('/', (req, res) => {
  res.send(`<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Todo App - Single File</title>
    <style>
      body { font-family: Arial, sans-serif; margin: 0; padding: 0; background: #f7f7f8; }
      .container { max-width: 780px; margin: 48px auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 6px 18px rgba(0,0,0,0.06); }
      h1 { margin: 0 0 12px; }
      form { display:flex; gap:8px; margin-bottom:12px; }
      input[type=text] { flex:1; padding:8px 12px; font-size:16px; border-radius:6px; border:1px solid #ddd; }
      button { padding:8px 12px; font-size:16px; border-radius:6px; border:none; cursor:pointer; }
      .todo { display:flex; align-items:center; justify-content:space-between; padding:10px; border-bottom:1px solid #eee; }
      .todo .left { display:flex; gap:12px; align-items:center; }
      .todo .text { font-size:16px; }
      .todo .text.completed { text-decoration: line-through; color: #888; }
      .actions button{ margin-left:8px; }
      .small { font-size:12px; color:#666 }
    </style>
  </head>
  <body>
    <div id="root" class="container"></div>

    <!-- React + ReactDOM + Babel via CDN for quick single-file demo -->
    <script src="https://unpkg.com/react@18/umd/react.development.js" crossorigin></script>
    <script src="https://unpkg.com/react-dom@18/umd/react-dom.development.js" crossorigin></script>
    <script src="https://unpkg.com/babel-standalone@6.26.0/babel.min.js"></script>

    <script type="text/babel">
      const { useState, useEffect } = React;

      function App(){
        const [todos, setTodos] = useState([]);
        const [text, setText] = useState('');
        const [loading, setLoading] = useState(false);

        useEffect(()=>{ fetchTodos(); }, []);

        async function fetchTodos(){
          setLoading(true);
          try{
            const res = await fetch('/api/todos');
            const data = await res.json();
            setTodos(data);
          }catch(e){ console.error(e); }
          setLoading(false);
        }

        async function addTodo(e){
          e.preventDefault();
          if(!text.trim()) return;
          try{
            const res = await fetch('/api/todos', { method: 'POST', headers: { 'Content-Type':'application/json' }, body: JSON.stringify({ text }) });
            const newTodo = await res.json();
            setTodos(prev => [newTodo, ...prev]);
            setText('');
          }catch(e){ console.error(e); }
        }

        async function toggleComplete(todo){
          try{
            const res = await fetch('/api/todos/'+todo._id, { method: 'PUT', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ completed: !todo.completed }) });
            const updated = await res.json();
            setTodos(prev => prev.map(t => t._id === updated._id ? updated : t));
          }catch(e){ console.error(e); }
        }

        async function deleteTodo(id){
          if(!confirm('Delete this todo?')) return;
          try{
            await fetch('/api/todos/'+id, { method: 'DELETE' });
            setTodos(prev => prev.filter(t => t._id !== id));
          }catch(e){ console.error(e); }
        }

        async function editTodo(todo){
          const newText = prompt('Edit todo text', todo.text);
          if(newText === null) return; // cancelled
          const trimmed = newText.trim();
          if(!trimmed) return alert('Text cannot be empty');
          try{
            const res = await fetch('/api/todos/'+todo._id, { method: 'PUT', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ text: trimmed }) });
            const updated = await res.json();
            setTodos(prev => prev.map(t => t._id === updated._id ? updated : t));
          }catch(e){ console.error(e); }
        }

        return (
          <div>
            <h1>Todo App</h1>
            <p className="small">Simple single-file full-stack demo (React + Express + MongoDB).</p>

            <form onSubmit={addTodo}>
              <input type="text" value={text} onChange={e=>setText(e.target.value)} placeholder="Add new todo..." />
              <button type="submit">Add</button>
            </form>

            {loading ? <p className="small">Loading...</p> : null}

            {todos.length === 0 && !loading ? <p className="small">No todos yet — add one above.</p> : (
              <div>
                {todos.map(todo => (
                  <div className="todo" key={todo._id}>
                    <div className="left">
                      <input type="checkbox" checked={todo.completed} onChange={()=>toggleComplete(todo)} />
                      <div className={"text" + (todo.completed ? ' completed' : '')}>{todo.text}</div>
                    </div>
                    <div className="actions">
                      <button onClick={()=>editTodo(todo)}>Edit</button>
                      <button onClick={()=>deleteTodo(todo._id)}>Delete</button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
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
