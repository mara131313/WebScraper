# WebScraper
## Project Overview
The goal of this project was to develop a tool capable of identifying whether a website is built using Shopify and, subsequently, detecting the entire tech stack used. The analysis is performed on a dataset of 200 domains provided in .parquet format.

## Development Journey
### Phase 1: Research & Technology Selection
Language: Python was chosen due to its powerful libraries for data processing and its efficiency in handling large datasets.  
Data Handling: Used pandas with the fastparquet engine to process the .snappy.parquet file. Snappy compression was noted as a key factor in how the root_domain column was stored.  
Instead of manually writing thousands of rules, I researched industry standards like Wappalyzer. I integrated an open-source version of the Wappalyzer technology database, providing 3,931 unique technology signatures.

### Phase 2: Access Optimization & Iteration
Initial attempts using only https and standard headers yielded 168/200 domains. By disabling "insecure request" warnings and implementing an http fallback, the success rate increased to 191/200. The remaining 9 failures consisted of 5 expired or deleted websites and 4 domains with high-level server protection.  
To reduce execution time, I implemented Parallel Programming using ThreadPoolExecutor. By tuning the max_workers to 30, I optimized the initial connection time from ~500s to under 60s.

### Phase 3: Integration of Signature Engine
I implemented a robust loader for the Wappalyzer JSON database. By utilizing os and json libraries, the script dynamically parses 3,931 signatures, mapping them into a searchable dictionary format.  
Initial Detection Logic: I started with basic string matching in the HTML body. Early results identified only 58 unique technologies and 463 total detections, confirming that a simple "search" was insufficient for modern web stacks.  
Then, to handle versioning and complex patterns, I integrated the "re" (Regular Expressions) module. This allowed for targeted scanning of specific attributes like scriptSrc and meta tags.

### Phase 4: Advanced Profiling & Depth Optimization
To increase accuracy, I expanded the engine to analyze multiple data points simultaneously:
- Headers & Cookies: extracting server information  and tracking pixels
- DOM & CSS Classes: identifying frontend frameworks by scanning class names in the HTML
- Iframe & Script Sources: detecting third-party widgets, maps, and external APIs
- Recursive Logic (Implies & Categorization): implemented the resolve_implies function which automatically detects hidden technologies based on parent ones
- Extended content discovery: To catch technologies not visible in the main index page, the script was optimized to fetch and scan:
  - top 10 external CSS files
  - ads.txt for advertising networks
  - /wp-json/ endpoints for WordPress API identification
  
This depth increased the unique technology count from 72 to 241 and total detections to over 10,000. However, the added network requests for CSS/extra files increased the execution time from 60s to ~200s, highlighting the classic balance between speed and data richness.

## Current Stats:
Accessed domains: *191 / 200*  
Unique technologies found: *241*  
Total detections (including implications): *~10,800*  
Domains with 0 technologies detected: *2*

## How To Run
### 1. Data preparation
Place input.snappy.parquet and the technologies/ folder in the root directory.
### 2. Dependencies instalation
    pip install pandas fastparquet requests urllib3
### 3. Execute
    python main.py
### 4. Output
The final stats are printed directly in the console, but if the full list of technologies and proofs for every domain is needed, everything can be found in output.json.

## Analysis & Future Improvements
### What were the main issues and how to tackle them?
The main problem with the current implementation is the fact that it uses static analysis (requests). It cannot see technologies rendered dynamically via JavaScript (React, Vue, etc.). To tackle the issue, I would use Playwright or Puppeteer to render the DOM before analysis.

Another problem is the server-side blocking, because some of the sites return 0 technologies (2 websites) or time out due to sophisticated anti-bot protections (9 websites). A solution would be to implement Proxy Rotation and more advanced header randomization to mimic a real user's behavior.

### How to scale for millions of domains (1-2 months)?
To process over millions domains within a two-month window, I would need to move away from a single-script approach and build a distributed architecture. My first step would be to transition to a microservices model, where the crawling, analysis, and storage are handled by separate units. I’d use a Message Queue to distribute the workload, sending domain URLs to a fleet of worker containers that can process data in parallel. 

To manage all this effectively, I’d deploy the workers on Kubernetes, which allows the system to auto-scale based on how many tasks are left in the queue. Since a simple JSON file wouldn't be able to handle millions of records, I’d replace it with a distributed NoSQL database like MongoDB, which is much better for high-speed indexing and complex searches. Finally, for those "difficult" websites that rely heavily on JavaScript, I’d set up a Headless Browser Farm to ensure we don't miss any technologies that aren't visible in the raw HTML.

### How to discover new technologies in the future?
The web is always changing, so I can’t just rely on the rules I have right now. To find new technologies, I would pay close attention to the sites where the tool currently finds nothing. If I start seeing thousands of these "anonymous" sites sharing the exact same new code patterns, it’s a clear sign that a new technology has arrived, and it’s time to create a signature for it.

I’d also want to keep an eye on what’s trending on platforms. When a new tool starts getting popular, I can study its digital footprint and automate a new rule for it. Another big help would be checking for .js.map files; they’re basically a map of the code that tells you exactly which packages were used to build the site. Lastly, I’d stay plugged into open-source communities like Wappalyzer to quickly pick up on new discoveries made by other developers in the field.

## License & Credits

This project is licensed under the **GNU GPLv3 License**.

Part of the web scraping logic (specifically the `technologies` folder) was adapted from [wappalyzer](https://github.com/dochne/wappalyzer?tab=GPL-3.0-1-ov-file) by Elbert Alias.