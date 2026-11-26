import { mount } from 'svelte';
import '../lib/setup.ts';
import App from './App.svelte';

const target = document.getElementById('app');
if (target === null) throw new Error('#app is missing');
mount(App, { target });
