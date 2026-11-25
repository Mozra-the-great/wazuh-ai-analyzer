import { mount } from 'svelte';
import '../lib/setup.ts';
import Login from './Login.svelte';

const target = document.getElementById('app');
if (target === null) throw new Error('#app is missing');
mount(Login, { target });
