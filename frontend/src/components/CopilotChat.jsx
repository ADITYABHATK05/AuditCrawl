import React, { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { copilotChat } from '../api';
import { useToast } from './ToastProvider';

export default function CopilotChat({ finding, onClose }) {
  const [messages, setMessages] = useState([
    { role: 'model', content: `Hello! I'm your AuditCrawl Copilot. I see you're looking at a **${finding.type}** finding on \`${finding.url || finding.endpoint || 'this endpoint'}\`. How can I help you remediate this?` }
  ]);
  const [input, setInput] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const messagesEndRef = useRef(null);
  const { addToast } = useToast();

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  const handleSend = async () => {
    if (!input.trim() || isLoading) return;
    
    const userMsg = { role: 'user', content: input };
    setMessages(prev => [...prev, userMsg]);
    setInput('');
    setIsLoading(true);
    
    try {
      const chatHistory = messages.filter(m => m.role !== 'system');
      const response = await copilotChat(userMsg.content, chatHistory, finding);
      
      setMessages(prev => [...prev, { role: 'model', content: response.response }]);
    } catch (err) {
      addToast(err.message || 'Failed to communicate with Copilot', 'critical');
      setMessages(prev => [...prev, { role: 'model', content: 'Sorry, I encountered an error. Please try again.' }]);
    } finally {
      setIsLoading(false);
    }
  };

  const handleKeyDown = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: 20 }}
      transition={{ type: 'spring', stiffness: 300, damping: 30 }}
      className="copilot-chat-container"
      style={{
        position: 'fixed',
        bottom: '20px',
        right: '20px',
        width: '400px',
        height: '550px',
        background: 'rgba(11, 17, 32, 0.95)',
        backdropFilter: 'blur(16px)',
        border: '1px solid var(--neon)',
        borderRadius: '16px',
        boxShadow: '0 10px 40px rgba(0,0,0,0.5), 0 0 20px rgba(0,229,160,0.1)',
        display: 'flex',
        flexDirection: 'column',
        zIndex: 9999,
        overflow: 'hidden'
      }}
    >
      {/* Header */}
      <div style={{
        padding: '1rem',
        borderBottom: '1px solid var(--border)',
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        background: 'rgba(0, 229, 160, 0.05)'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <span style={{ fontSize: '1.2rem' }}>🤖</span>
          <div>
            <div style={{ fontFamily: 'var(--display)', fontWeight: 600, color: 'white', fontSize: '1rem' }}>AuditCrawl Copilot</div>
            <div style={{ fontSize: '0.7rem', color: 'var(--neon)' }}>Security Assistant Online</div>
          </div>
        </div>
        <button 
          onClick={onClose}
          style={{ background: 'transparent', border: 'none', color: 'var(--text)', cursor: 'pointer', padding: '0.2rem', fontSize: '1.2rem' }}
        >
          ✕
        </button>
      </div>

      {/* Messages */}
      <div style={{
        flex: 1,
        padding: '1rem',
        overflowY: 'auto',
        display: 'flex',
        flexDirection: 'column',
        gap: '1rem'
      }}>
        {messages.map((msg, idx) => (
          <div key={idx} style={{
            alignSelf: msg.role === 'user' ? 'flex-end' : 'flex-start',
            maxWidth: '85%',
            background: msg.role === 'user' ? 'rgba(64,170,255,0.1)' : 'rgba(30,41,59,0.5)',
            border: `1px solid ${msg.role === 'user' ? 'rgba(64,170,255,0.3)' : 'var(--border)'}`,
            padding: '0.75rem 1rem',
            borderRadius: '12px',
            borderBottomRightRadius: msg.role === 'user' ? 0 : '12px',
            borderBottomLeftRadius: msg.role === 'user' ? '12px' : 0,
            color: 'var(--text)',
            fontSize: '0.85rem',
            lineHeight: 1.5,
            whiteSpace: 'pre-wrap'
          }}>
            {msg.content}
          </div>
        ))}
        {isLoading && (
          <div style={{ alignSelf: 'flex-start', color: 'var(--muted)', fontSize: '0.8rem' }}>
            Copilot is thinking...
          </div>
        )}
        <div ref={messagesEndRef} />
      </div>

      {/* Input */}
      <div style={{
        padding: '1rem',
        borderTop: '1px solid var(--border)',
        background: 'rgba(2, 6, 23, 0.5)'
      }}>
        <div style={{ display: 'flex', gap: '0.5rem' }}>
          <textarea
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="Ask how to fix this..."
            disabled={isLoading}
            style={{
              flex: 1,
              background: 'var(--surface)',
              border: '1px solid var(--border)',
              borderRadius: '8px',
              padding: '0.5rem 0.75rem',
              color: 'white',
              fontSize: '0.85rem',
              resize: 'none',
              outline: 'none',
              fontFamily: 'inherit',
              height: '40px',
              minHeight: '40px'
            }}
          />
          <button
            onClick={handleSend}
            disabled={!input.trim() || isLoading}
            style={{
              background: input.trim() && !isLoading ? 'var(--neon)' : 'var(--border)',
              color: input.trim() && !isLoading ? 'var(--bg)' : 'var(--muted)',
              border: 'none',
              borderRadius: '8px',
              padding: '0 1rem',
              cursor: input.trim() && !isLoading ? 'pointer' : 'not-allowed',
              fontWeight: 600
            }}
          >
            Send
          </button>
        </div>
      </div>
    </motion.div>
  );
}
