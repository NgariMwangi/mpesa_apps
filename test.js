console.log("Start");
setTimeout(() => console.log("Async Task"), 0);
console.log("End");
// Output: Start -> End -> Async Task (after 2s)
