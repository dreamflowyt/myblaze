document.addEventListener('DOMContentLoaded', function() {
    // Socket.IO connection
    const socket = io();
    
    // DOM Elements
    const messageForm = document.getElementById('message-form');
    const messageInput = document.getElementById('message');
    const chatHistory = document.getElementById('chat-history');
    const roomId = chatHistory.dataset.roomId;
    const typingIndicator = document.getElementById('typing-indicator');
    
    // Mobile viewport adjustments
    function adjustViewportForMobile() {
        // Check if mobile device
        const isMobile = window.innerWidth <= 768;
        
        if (isMobile) {
            // Make sure content doesn't overflow unnecessarily
            document.documentElement.style.height = `${window.innerHeight}px`;
            document.body.style.height = `${window.innerHeight}px`;
            
            // Apply a delay to scrollToBottom to account for virtual keyboard
            if (document.activeElement === messageInput) {
                setTimeout(scrollToBottom, 300);
            }
        }
    }
    
    // Set initial viewport
    adjustViewportForMobile();
    
    // Update on resize or orientation change
    window.addEventListener('resize', adjustViewportForMobile);
    window.addEventListener('orientationchange', function() {
        setTimeout(adjustViewportForMobile, 200);
        setTimeout(scrollToBottom, 300);
    });
    
    // Join room on connection
    socket.on('connect', function() {
        socket.emit('join', {room: roomId});
        console.log('Connected to room:', roomId);
    });
    
    // Leave room before page unload
    window.addEventListener('beforeunload', function() {
        socket.emit('leave', {room: roomId});
    });
    
    // Handle incoming messages
    socket.on('message', function(data) {
        addMessage(data.id, data.username, data.message, data.timestamp, data.reactions);
        scrollToBottom();
    });
    
    // Handle reaction updates
    socket.on('reaction_update', function(data) {
        updateMessageReactions(data.message_id, data.reactions, data.user_reactions);
    });
    
    // Handle status messages (join/leave)
    socket.on('status', function(data) {
        addSystemMessage(data.msg);
        scrollToBottom();
    });
    
    // Send message on form submit
    messageForm.addEventListener('submit', function(e) {
        e.preventDefault();
        
        const message = messageInput.value.trim();
        if (message) {
            // Emit message to server
            socket.emit('message', {
                room: roomId,
                message: message
            });
            
            // Clear input
            messageInput.value = '';
            
            // Handle focus differently on mobile vs desktop
            if (window.innerWidth > 768) {
                // On desktop, keep focus on input for continued typing
                messageInput.focus();
            } else {
                // On mobile, blur focus to hide keyboard after sending
                // This gives more screen space to see the new message
                messageInput.blur();
                
                // Scroll to bottom after a short delay to ensure the message is visible
                setTimeout(scrollToBottom, 100);
            }
        }
    });
    
    // Handle mobile keyboard appearance and disappearance
    messageInput.addEventListener('focus', function() {
        // On mobile, when keyboard appears, scroll to bottom after a short delay
        if (window.innerWidth <= 768) {
            setTimeout(scrollToBottom, 300);
        }
    });
    
    messageInput.addEventListener('blur', function() {
        // On mobile, when keyboard disappears, scroll to bottom
        if (window.innerWidth <= 768) {
            setTimeout(scrollToBottom, 100);
        }
    });
    
    // Typing indicator
    let typingTimeout;
    messageInput.addEventListener('input', function() {
        clearTimeout(typingTimeout);
        
        // Hide typing after 2 seconds of inactivity
        typingTimeout = setTimeout(() => {
            // You could emit a 'stop typing' event here
        }, 2000);
    });
    
    // Add message to chat history
    function addMessage(id, username, message, timestamp, reactions = {}) {
        const messageElement = document.createElement('div');
        messageElement.className = 'message';
        messageElement.dataset.messageId = id;
        
        // Format timestamp for mobile (shorter format on small screens)
        let formattedTimestamp = timestamp;
        if (window.innerWidth <= 576) {
            // If it's a full datetime string, shorten it
            if (timestamp.includes(' ')) {
                // Extract just the time portion
                formattedTimestamp = timestamp.split(' ')[1];
            }
        }
        
        // Create reaction HTML
        const reactionButtons = `
            <div class="message-reactions mt-1">
                <div class="reaction-counts" id="reaction-counts-${id}">
                    ${renderReactionCounts(reactions)}
                </div>
                <div class="reaction-buttons">
                    <button class="btn btn-sm reaction-btn" data-reaction="like" data-message-id="${id}">👍</button>
                    <button class="btn btn-sm reaction-btn" data-reaction="heart" data-message-id="${id}">❤️</button>
                    <button class="btn btn-sm reaction-btn" data-reaction="laugh" data-message-id="${id}">😂</button>
                    <button class="btn btn-sm reaction-btn" data-reaction="wow" data-message-id="${id}">😮</button>
                    <button class="btn btn-sm reaction-btn" data-reaction="sad" data-message-id="${id}">😢</button>
                    <button class="btn btn-sm reaction-btn" data-reaction="angry" data-message-id="${id}">😠</button>
                </div>
            </div>
        `;
        
        const messageContent = `
            <div class="d-flex justify-content-between align-items-center mb-1">
                <span class="username">${escapeHtml(username)}</span>
                <span class="timestamp">${formattedTimestamp}</span>
            </div>
            <div class="content">${escapeHtml(message)}</div>
            ${reactionButtons}
        `;
        
        messageElement.innerHTML = messageContent;
        chatHistory.appendChild(messageElement);
        
        // Add event listeners to reaction buttons
        messageElement.querySelectorAll('.reaction-btn').forEach(button => {
            button.addEventListener('click', handleReaction);
        });
        
        // Prune message history if it gets too long (mobile performance)
        if (window.innerWidth <= 768 && chatHistory.children.length > 100) {
            // Remove the oldest messages if we have more than 100
            while (chatHistory.children.length > 100) {
                chatHistory.removeChild(chatHistory.firstChild);
            }
        }
    }
    
    // Handle message reaction click
    function handleReaction(event) {
        const messageId = event.target.dataset.messageId;
        const reactionType = event.target.dataset.reaction;
        
        fetch(`/api/messages/${messageId}/react`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Requested-With': 'XMLHttpRequest'
            },
            body: JSON.stringify({ reaction_type: reactionType })
        })
        .catch(error => console.error('Error sending reaction:', error));
    }
    
    // Render reaction counts for a message
    function renderReactionCounts(reactions) {
        if (!reactions || Object.keys(reactions).length === 0) {
            return '';
        }
        
        return Object.entries(reactions).map(([type, count]) => {
            const emoji = getReactionEmoji(type);
            return `<span class="reaction-count" data-reaction="${type}">${emoji} ${count}</span>`;
        }).join(' ');
    }
    
    // Update message reactions
    function updateMessageReactions(messageId, reactions, userReactions = []) {
        const messageElement = document.querySelector(`.message[data-message-id="${messageId}"]`);
        if (!messageElement) return;
        
        // Update reaction counts
        const countsElement = messageElement.querySelector(`#reaction-counts-${messageId}`);
        if (countsElement) {
            countsElement.innerHTML = renderReactionCounts(reactions);
        }
        
        // Update reaction buttons to highlight user's reactions
        messageElement.querySelectorAll('.reaction-btn').forEach(button => {
            if (userReactions.includes(button.dataset.reaction)) {
                button.classList.add('active');
            } else {
                button.classList.remove('active');
            }
        });
    }
    
    // Get emoji for reaction type
    function getReactionEmoji(type) {
        const emojis = {
            'like': '👍',
            'heart': '❤️',
            'laugh': '😂',
            'wow': '😮',
            'sad': '😢',
            'angry': '😠'
        };
        return emojis[type] || '';
    }
    
    // Add system message to chat history
    function addSystemMessage(message) {
        const messageElement = document.createElement('div');
        messageElement.className = 'system-message';
        messageElement.textContent = message;
        chatHistory.appendChild(messageElement);
    }
    
    // Scroll chat to bottom
    function scrollToBottom() {
        chatHistory.scrollTop = chatHistory.scrollHeight;
    }
    
    // Initial scroll to bottom
    scrollToBottom();
    
    // Escape HTML to prevent XSS
    function escapeHtml(unsafe) {
        return unsafe
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }
});
