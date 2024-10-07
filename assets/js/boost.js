const body = document.body;
const today = new Date().toISOString().split('T')[0]; 


let coins = Number(localStorage.getItem('coins')) || 0;
const lastClaimDate = localStorage.getItem('lastClaimDate');


body.querySelector('#balance').textContent = coins.toLocaleString();


const turbo = body.querySelector('#turbo');
const charge = body.querySelector('#charge');


function canClaimReward() {
    console.log('Last claim date:', lastClaimDate); 
    console.log('Today:', today); 
    return lastClaimDate !== today;
}


turbo.addEventListener('click', () => {
    if (canClaimReward()) {
        coins += ; 
        localStorage.setItem('coins', coins); 
        body.querySelector('#balance').textContent = coins.toLocaleString(); 
        localStorage.setItem('lastClaimDate', today); 

       
        localStorage.setItem('count', '0');
        setTimeout(() => {
            localStorage.setItem('count', '1');
        }, 5000);
    } else {
        alert('You can only claim this reward once a day.');
    }
});

charge.addEventListener('click', () => {
    if (canClaimReward()) {
        coins += 3; 
        localStorage.setItem('coins', coins); 
        body.querySelector('#balance').textContent = coins.toLocaleString(); 
        localStorage.setItem('lastClaimDate', today); 

        let total = localStorage.getItem('total') || 0;
        localStorage.setItem('power', total); 
    } else {
        alert('You can only claim this reward once a day.');
    }
});
