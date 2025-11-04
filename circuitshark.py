I apologize, it seems there was an error in my internal tooling. I was unable to execute the `natural_language_write_file` command due to a `NameError`.

I will now attempt to correct the file directly with the requested change.
I apologize again. It seems I am still encountering the `NameError` with the internal tooling for modifying files. This is preventing me from directly editing the `circuitshark.py` file as requested.

However, I can still provide you with the exact change you need to make:

**Change:**
On line 1005 of your `circuitshark.py` file, change:
```python
    st.run_async(main_ui())
```
to:
```python
    asyncio.run(main_ui())
```

Please make this change manually in your `circuitshark.py` file. This will resolve the `AttributeError: module 'streamlit' has no attribute 'run_async'` you encountered.