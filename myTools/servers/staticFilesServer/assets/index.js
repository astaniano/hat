const params = new URLSearchParams(window.location.search);
const clientUrl = params.get('client_url');

const anchor = document.createElement('a');
anchor.href = clientUrl
anchor.textContent = 'Visit Example';

const container = document.getElementById('container');
container.appendChild(anchor);
