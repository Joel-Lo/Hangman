const wordDisplay = document.querySelector(".word-display");
const guessesText = document.querySelector(".guesses-text b");
const keyboardDiv = document.querySelector(".keyboard");
const hangmanImage = document.querySelector(".hangman-box img");
const gameModal = document.querySelector(".game-modal");
const playAgainBtn = gameModal.querySelector("button");

let currentWord, correctLetters, wrongGuessCount;
const maxGuesses = 6;

const resetGame = () => {
    correctLetters = [];
    wrongGuessCount = 0;
    hangmanImage.src = "hangman-0.svg";
    guessesText.innerText = `${wrongGuessCount} / ${maxGuesses}`;

    const lowerCaseWord = currentWord.toLowerCase();

    wordDisplay.innerHTML = lowerCaseWord.split("").map(letter => {
        if (letter === ' ') {
            correctLetters.push(' ');
            return `<span class="space-separator">${letter}</span>`;
        }
        return `<li class="letter"></li>`;
    }).join("");

    keyboardDiv.querySelectorAll("button").forEach(btn => btn.disabled = false);
    gameModal.classList.remove("show");
}

const getRandomWord = () => {
    const { word, hint } = wordList[Math.floor(Math.random() * wordList.length)];
    currentWord = word;
    document.querySelector(".hint-text b").innerText = hint;
    resetGame();
}

const gameOver = (isVictory) => {
    const modalText = isVictory ? `You found the phrase:` : 'The correct phrase was:';
    gameModal.querySelector("img").src = `${isVictory ? 'victory' : 'lost'}.gif`;
    gameModal.querySelector("h4").innerText = isVictory ? 'Congrats!' : 'Game Over!';
    gameModal.querySelector("p").innerHTML = `${modalText} <b>${currentWord}</b>`;
    gameModal.classList.add("show");
}

const initGame = (button, clickedLetter) => {
    const lowerCaseWord = currentWord.toLowerCase();
    let letterIndex = 0;

    if(lowerCaseWord.includes(clickedLetter)) {
        [...lowerCaseWord].forEach((letter, index) => {
            if(letter !== ' ') {
                if(letter === clickedLetter) {
                    correctLetters.push(letter);

                    wordDisplay.querySelectorAll("li")[letterIndex].innerText = currentWord[index];
                    wordDisplay.querySelectorAll("li")[letterIndex].classList.add("guessed");
                }
                letterIndex++;
            }
        });
    } else {
        wrongGuessCount++;
        hangmanImage.src = `hangman-${wrongGuessCount}.svg`;
    }

    button.disabled = true;
    guessesText.innerText = `${wrongGuessCount} / ${maxGuesses}`;

    if(wrongGuessCount === maxGuesses) return gameOver(false);

    if(correctLetters.length === lowerCaseWord.length) return gameOver(true);
}

for (let i = 97; i <= 122; i++) {
    const button = document.createElement("button");
    button.innerText = String.fromCharCode(i);
    keyboardDiv.appendChild(button);
    button.addEventListener("click", (e) => initGame(e.target, String.fromCharCode(i)));
}

const spaceButton = document.createElement("button");
spaceButton.innerText = "Space";
keyboardDiv.appendChild(spaceButton);

spaceButton.addEventListener("click", (e) => {
    wrongGuessCount++;
    hangmanImage.src = `hangman-${wrongGuessCount}.svg`;
    e.target.disabled = true;
    guessesText.innerText = `${wrongGuessCount} / ${maxGuesses}`;

    wordDisplay.querySelectorAll(".space-separator").forEach(spaceEl => {
        spaceEl.classList.add("space-pressed");
    });

    if(wrongGuessCount === maxGuesses) return gameOver(false);
    if(correctLetters.length === currentWord.toLowerCase().length) return gameOver(true);
});

Swal.fire({
    title: 'Welcome!',
    text: 'Some words may have more than 1 word.',
    showConfirmButton: false,
    showCancelButton: false,
    allowOutsideClick: false,
    timer: 3000,
}).then((result) => {
    if (result.dismiss === Swal.DismissReason.timer || result.isConfirmed) {
        getRandomWord();
    }
});

playAgainBtn.addEventListener("click", getRandomWord);
