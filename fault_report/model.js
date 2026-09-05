/* Pure page-coordinate helpers. Keep BigInt until after page alignment. */
globalThis.FaultModel = (() => {
  function page(event, pageSize) {
    if (event.addressPlot === false) return null;
    return BigInt(event.address) / BigInt(pageSize);
  }
  function deltas(events, pageSize, space) {
    const result = [];
    for (let i = 1; i < events.length; i++) {
      const event = events[i],
        previous = events[i - 1];
      if (
        space === "file" &&
        (event.page === null ||
          previous.page === null ||
          event.source !== previous.source)
      )
        continue;
      if (
        space !== "file" &&
        (page(event, pageSize) === null || page(previous, pageSize) === null)
      )
        continue;
      const value =
        space === "file"
          ? event.page - previous.page
          : Number(page(event, pageSize) - page(previous, pageSize));
      result.push({ event, previous, value });
    }
    return result;
  }
  function median(values) {
    if (!values.length) return null;
    const sorted = values.slice().sort((a, b) => a - b);
    return (
      (sorted[Math.floor((sorted.length - 1) / 2)] +
        sorted[Math.floor(sorted.length / 2)]) /
      2
    );
  }
  return { page, deltas, median };
})();
