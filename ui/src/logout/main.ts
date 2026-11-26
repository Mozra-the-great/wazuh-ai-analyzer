import { mount } from 'svelte';
import '../lib/setup.ts';
import Logout from './Logout.svelte';

const target = document.getElementById('app');
if (target === null) throw new Error('#app is missing');
mount(Logout, { target });
