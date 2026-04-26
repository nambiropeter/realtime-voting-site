const socket = io();

const questionEl = document.querySelector("#question");
const totalVotesEl = document.querySelector("#total-votes");
const onlineEl = document.querySelector("#online");
const statusEl = document.querySelector("#status");
const optionsEl = document.querySelector("#options");
const optionTemplate = document.querySelector("#option-template");

let selectedOptionId = null;
let currentPoll = null;

function formatVotes(totalVotes) {
  return totalVotes === 1 ? "1 vote" : `${totalVotes} votes`;
}

function showStatus(message, tone = "") {
  statusEl.textContent = message;
  statusEl.className = tone ? `status ${tone}` : "status";
}

function renderPoll(poll) {
  currentPoll = poll;
  questionEl.textContent = poll.question;
  totalVotesEl.textContent = formatVotes(poll.totalVotes);
  optionsEl.replaceChildren();

  for (const option of poll.options) {
    const optionNode = optionTemplate.content.firstElementChild.cloneNode(true);
    const labelEl = optionNode.querySelector(".label");
    const valueEl = optionNode.querySelector(".value");
    const barEl = optionNode.querySelector(".bar");

    const ratio = poll.totalVotes > 0 ? option.votes / poll.totalVotes : 0;
    const percent = Math.round(ratio * 100);

    optionNode.dataset.optionId = option.id;
    labelEl.textContent = option.label;
    valueEl.textContent = `${option.votes} (${percent}%)`;
    barEl.style.width = `${percent}%`;

    if (selectedOptionId === option.id) {
      optionNode.classList.add("selected");
      optionNode.setAttribute("aria-pressed", "true");
    } else {
      optionNode.setAttribute("aria-pressed", "false");
    }

    optionNode.addEventListener("click", () => {
      showStatus("Submitting vote...");
      socket.emit("poll:vote", { optionId: option.id });
    });

    optionsEl.append(optionNode);
  }
}

socket.on("connect", () => {
  showStatus("Connected", "ok");
  if (selectedOptionId) {
    socket.emit("poll:vote", { optionId: selectedOptionId });
  }
});

socket.on("poll:update", (poll) => {
  renderPoll(poll);
  showStatus("");
});

socket.on("poll:your-vote", ({ optionId }) => {
  selectedOptionId = optionId;
  showStatus("Vote saved", "ok");
  if (currentPoll) {
    renderPoll(currentPoll);
  }
});

socket.on("presence:update", ({ online }) => {
  onlineEl.textContent = `${online} online`;
});

socket.on("poll:error", ({ message }) => {
  showStatus(message || "Unable to submit vote right now.", "error");
});

socket.on("connect_error", () => {
  showStatus("Connection blocked. Refresh and try again.", "error");
});

socket.on("disconnect", () => {
  showStatus("Disconnected. Reconnecting...", "warn");
});
