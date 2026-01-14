document.addEventListener("DOMContentLoaded", function () {
    const form = document.getElementById("chat-form");
    const input = document.getElementById("user-input");
    const chatBox = document.getElementById("chat-messages");

    form.addEventListener("submit", async function (event) {
        event.preventDefault(); // prevent reload
        const userMessage = input.value.trim();
        if (!userMessage) return;

        // display user message
        chatBox.innerHTML += `<p><strong>You:</strong> ${userMessage}</p>`;
        input.value = "";

        try {
            const response = await fetch("/ai_helper_chat", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ message: userMessage })
            });

            const data = await response.json();

            if (data.reply) {
                chatBox.innerHTML += `<p><strong>AI:</strong> ${data.reply}</p>`;
            } else {
                chatBox.innerHTML += `<p><strong>AI:</strong> ⚠️ Sorry, I couldn’t understand that.</p>`;
            }
        } catch (error) {
            chatBox.innerHTML += `<p><strong>AI:</strong> ⚠️ Error connecting to AI backend.</p>`;
            console.error("Error:", error);
        }

        chatBox.scrollTop = chatBox.scrollHeight;
    });
});
