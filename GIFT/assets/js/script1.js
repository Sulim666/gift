
let balance = 0; 


function updateBalance() {
    document.getElementById('balance').textContent = balance;
}


function handleTurboClick() {
    balance += 60;
    updateBalance();
}


function handleFullEnergyClick() {
    balance += 100;
    updateBalance();
}


document.getElementById('turbo').addEventListener('click', handleTurboClick);
document.getElementById('charge').addEventListener('click', handleFullEnergyClick);


updateBalance();
