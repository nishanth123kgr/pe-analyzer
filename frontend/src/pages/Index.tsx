import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Progress } from "@/components/ui/progress";
import { HoverCard, HoverCardContent, HoverCardTrigger } from "@/components/ui/hover-card";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { useToast } from "@/hooks/use-toast";
import { useState, useRef, useEffect } from "react";
import { 
  CheckCircle, 
  AlertTriangle, 
  FileSearch, 
  FilesIcon, 
  Database, 
  Code, 
  ChevronDown, 
  ExternalLink, 
  Lock, 
  Upload,
  Hexagon,
  Sparkles,
  Activity,
  Globe,
  Github
} from "lucide-react";

// WebAssembly Module interface for TypeScript
interface PEAnalyzerModule {
  _malloc: (size: number) => number;
  _free: (ptr: number) => void;
  _analyze_pe_buffer: (bufferPtr: number, size: number) => number;
  HEAPU8: Uint8Array;
  UTF8ToString: (ptr: number) => string;
}

// Declare the global PEAnalyzer variable that will be loaded from the WASM script
declare global {
  interface Window {
    PEAnalyzer: () => Promise<PEAnalyzerModule>;
  }
}

const Index = () => {
  const { toast } = useToast();
  const [file, setFile] = useState<File | null>(null);
  const [analyzing, setAnalyzing] = useState(false);
  const [analysisData, setAnalysisData] = useState<any>(null);
  const [moduleLoaded, setModuleLoaded] = useState(false);
  const [loadingProgress, setLoadingProgress] = useState(0);
  const [showUpload, setShowUpload] = useState(true);
  const [wasmModule, setWasmModule] = useState<PEAnalyzerModule | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const dropAreaRef = useRef<HTMLDivElement>(null);
  
  // Load the actual WebAssembly module
  useEffect(() => {
    // Create a script element to load the PE analyzer WASM module
    const script = document.createElement('script');
    script.src = '/pe_analyzer.js'; // Path to the WASM JavaScript loader
    script.async = true;
    
    // Set up loading progress indicators
    const loadSteps = [25, 50, 75, 90];
    let currentStep = 0;
    
    // Show initial loading state
    setLoadingProgress(10);
    
    script.onload = () => {
      // Script loaded, now initialize the module
      setLoadingProgress(loadSteps[currentStep++]);
      
      // Check if PEAnalyzer is available in the global scope
      if (typeof window.PEAnalyzer === 'function') {
        try {
          // Initialize the WASM module - PEAnalyzer() returns a Promise
          const modulePromise = window.PEAnalyzer();
          
          // Update progress as we wait for the Promise
          setLoadingProgress(loadSteps[currentStep++]);
          
          modulePromise
            .then((moduleInstance) => {
              setLoadingProgress(100);
              setWasmModule(moduleInstance);
              setModuleLoaded(true);
              console.log("PE Analyzer WebAssembly module loaded successfully");
            })
            .catch((error: any) => {
              console.error("Error initializing PE Analyzer WebAssembly module:", error);
              toast({
                variant: "destructive",
                title: "Module Loading Error",
                description: "Failed to initialize the PE analyzer module.",
              });
            });
        } catch (error) {
          console.error("Error creating PE Analyzer module instance:", error);
          toast({
            variant: "destructive",
            title: "Module Loading Error",
            description: "Failed to create PE Analyzer instance.",
          });
        }
      } else {
        console.error("PEAnalyzer function not found in global scope after script loaded");
        console.log("Window object keys:", Object.keys(window));
        toast({
          variant: "destructive",
          title: "Module Loading Error",
          description: "PE Analyzer module failed to load correctly.",
        });
      }
    };
    
    script.onerror = (event) => {
      console.error("Error loading PE Analyzer WebAssembly script:", event);
      toast({
        variant: "destructive",
        title: "Module Loading Error",
        description: "Failed to load the PE analyzer module script.",
      });
    };
    
    // Add the script to the document to start loading
    document.body.appendChild(script);
    
    // Cleanup function
    return () => {
      if (document.body.contains(script)) {
        document.body.removeChild(script);
      }
    };
  }, [toast]);
  
  const handleFileChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    if (event.target.files && event.target.files.length > 0) {
      setFile(event.target.files[0]);
    }
  };
  
  const handleDrop = (event: React.DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    event.stopPropagation();
    
    if (dropAreaRef.current) {
      dropAreaRef.current.classList.remove("border-red-500/50");
      dropAreaRef.current.classList.add("border-white/20");
    }
    
    if (event.dataTransfer.files && event.dataTransfer.files.length > 0) {
      setFile(event.dataTransfer.files[0]);
    }
  };
  
  const handleDragOver = (event: React.DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    event.stopPropagation();
    
    if (dropAreaRef.current) {
      dropAreaRef.current.classList.remove("border-white/20");
      dropAreaRef.current.classList.add("border-red-500/50");
    }
  };
  
  const handleDragLeave = (event: React.DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    event.stopPropagation();
    
    if (dropAreaRef.current) {
      dropAreaRef.current.classList.remove("border-red-500/50");
      dropAreaRef.current.classList.add("border-white/20");
    }
  };
  
  const analyzeFile = async () => {
    if (!file || !moduleLoaded || !wasmModule) return;
    
    setAnalyzing(true);
    
    try {
      // Read the file as ArrayBuffer
      const fileBuffer = await file.arrayBuffer();
      const fileData = new Uint8Array(fileBuffer);
      
      // Allocate memory in WASM for the file data
      const fileSize = fileData.length;
      const filePtr = wasmModule._malloc(fileSize);
      
      // Copy the file data to WASM memory
      wasmModule.HEAPU8.set(fileData, filePtr);
      
      console.log(`Analyzing file: ${file.name} (${fileSize} bytes)`);
      
      // Call the WASM analyze_pe_buffer function
      const resultPtr = wasmModule._analyze_pe_buffer(filePtr, fileSize);
      
      // Free the file buffer memory
      wasmModule._free(filePtr);
      
      if (resultPtr === 0) {
        throw new Error("Analysis failed - invalid PE file or unsupported format");
      }
      
      // Get the result as a JSON string and parse it
      const resultJson = wasmModule.UTF8ToString(resultPtr);
      const analysisResult = JSON.parse(resultJson);
      
      console.log("Analysis complete", analysisResult);
      
      // Free the result memory
      wasmModule._free(resultPtr);
      
      // Update the UI with the analysis data
      setAnalysisData(analysisResult);
      setShowUpload(false); // Hide upload after analysis
      
      toast({
        title: "Analysis Complete",
        description: `Successfully analyzed ${file.name}`,
      });
    } catch (error) {
      console.error("Error analyzing file:", error);
      toast({
        variant: "destructive",
        title: "Analysis Failed",
        description: error instanceof Error ? error.message : "An error occurred during the analysis.",
      });
    } finally {
      setAnalyzing(false);
    }
  };

  return (
    <div className="min-h-screen bg-[radial-gradient(ellipse_at_top,_var(--tw-gradient-stops))] from-[#1A1F2C] via-[#221F26] to-black overflow-hidden">
      {/* Background grid pattern */}
      <div className="absolute top-0 left-0 w-full h-full bg-[url('data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSI1IiBoZWlnaHQ9IjUiPgo8cmVjdCB3aWR0aD0iNSIgaGVpZ2h0PSI1IiBmaWxsPSIjMDAwMDAwMDUiPjwvcmVjdD4KPHBhdGggZD0iTTAgNUw1IDBaTTYgNEw0IDZaTS0xIDFMMSAtMVoiIHN0cm9rZT0iI2ZmZmZmZjA1IiBzdHJva2Utd2lkdGg9IjAuNSI+PC9wYXRoPgo8L3N2Zz4=')] opacity-10"></div>
      
      <div className="relative z-10 max-w-screen-xl mx-auto p-4 md:p-6 lg:p-8">
        {/* Enhanced modern top header */}
        <div className="glass-morphism rounded-2xl mb-8 p-4 md:p-6 overflow-hidden relative">
          {/* Background patterns for visual interest */}
          <div className="absolute -right-20 -top-20 w-64 h-64 rounded-full bg-purple-500/10 blur-3xl"></div>
          <div className="absolute -left-20 -bottom-20 w-64 h-64 rounded-full bg-red-500/10 blur-3xl"></div>
          
          <div className="relative flex flex-col md:flex-row md:items-center md:justify-between">
            <div className="flex items-start gap-4">
              {/* Modern icon with hexagon for more dynamic look */}
              <div className="relative">
                <div className="w-14 h-14 flex items-center justify-center">
                  <Hexagon className="w-14 h-14 text-red-500/30 absolute animate-pulse" strokeWidth={1.5} />
                  <Hexagon className="w-12 h-12 text-red-500/50 absolute rotate-45" strokeWidth={1.5} />
                  <Activity className="w-6 h-6 text-red-400 relative z-10" strokeWidth={2} />
                  <div className="absolute w-full h-full inset-0 bg-gradient-to-br from-red-500/5 to-transparent rounded-xl blur-sm"></div>
                </div>
                {/* Sparkle for visual effect */}
                <Sparkles className="w-4 h-4 text-red-300 absolute -right-1 -top-1 animate-pulse" />
              </div>
              
              <div className="flex-1">
                <div className="flex items-center gap-3">
                  <h1 className="text-3xl md:text-4xl font-bold bg-gradient-to-br from-white via-red-100 to-red-300 bg-clip-text text-transparent">
                    PE Analyzer
                  </h1>
                  <div className="h-6 border-l border-white/10"></div>
                  <div className="flex items-center gap-2">
                    <span className="text-xs uppercase tracking-wider text-gray-400 bg-black/20 px-2 py-1 rounded-md">
                      v1.2.0
                    </span>
                    {/* In Browser Tag */}
                    <div className="flex items-center gap-1.5 bg-gradient-to-r from-purple-500/20 to-blue-500/20 border border-purple-500/30 px-2 py-1 rounded-md animate-fade-in">
                      <Globe className="w-3 h-3 text-purple-300" />
                      <span className="text-xs font-medium text-purple-200">In Browser</span>
                    </div>
                  </div>
                </div>
                <p className="text-gray-400 mt-1 max-w-xl">
                  Advanced binary analysis for executable files with real-time insights
                </p>
              </div>
            </div>

            {/* Right side action buttons */}
            <div className="flex gap-3 mt-4 md:mt-0">
              <Button 
                variant="outline"
                size="sm"
                className="text-gray-300 bg-black/20 border-white/10 hover:bg-white/5 transition-all"
                onClick={() => window.open('https://github.com/nishanth123kgr/pe-analyzer', '_blank')}
              >
                <Github className="w-4 h-4" />
                GitHub
              </Button>
            </div>
          </div>
        </div>
        
        {/* Main content area with conditional rendering */}
        <div className="grid grid-cols-1 gap-6 lg:gap-8">
          {/* Centered upload card when no analysis is shown */}
          {(showUpload && !analysisData) && (
            <div className="mx-auto w-full max-w-xl">
              {/* File upload card */}
              <div className="glass-morphism rounded-xl p-5 transform transition-all hover:translate-y-[-2px] hover:shadow-[0_8px_20px_-2px_rgba(255,0,0,0.15)]">
                <div className="flex items-center gap-3 mb-4">
                  <div className="w-9 h-9 rounded-full bg-gradient-to-br from-red-500/20 to-red-700/10 flex items-center justify-center">
                    <FileSearch className="w-4 h-4 text-red-400" />
                  </div>
                  <div>
                    <h2 className="text-base font-semibold text-white">Upload File</h2>
                    <p className="text-xs text-gray-400">Select PE, EXE, DLL files</p>
                  </div>
                </div>
                
                <div
                  ref={dropAreaRef}
                  className="border-2 border-dashed border-white/20 rounded-lg p-8 text-center cursor-pointer transition-all hover:border-red-400/30 mb-4 group"
                  onClick={() => fileInputRef.current?.click()}
                  onDrop={handleDrop}
                  onDragOver={handleDragOver}
                  onDragLeave={handleDragLeave}
                >
                  <input 
                    type="file" 
                    ref={fileInputRef}
                    className="hidden" 
                    onChange={handleFileChange} 
                  />
                  <div className="flex flex-col items-center gap-2">
                    <div className="w-14 h-14 rounded-full bg-black/30 flex items-center justify-center group-hover:scale-110 transition-transform">
                      <FilesIcon className="w-7 h-7 text-gray-500 group-hover:text-red-400 transition-colors" />
                    </div>
                    <p className="text-sm text-gray-300">
                      <span className="font-medium">Click to upload</span> or drag and drop
                    </p>
                    <p className="text-xs text-gray-500">PE, EXE, DLL, SYS files</p>
                  </div>
                </div>
                
                {file && (
                  <div className="mb-4 p-3 neo-blur rounded-lg border border-white/10 animate-fade-in">
                    <div className="flex items-center gap-2">
                      <div className="w-8 h-8 flex items-center justify-center rounded-full bg-gradient-to-br from-red-500/20 to-red-700/10">
                        <FilesIcon className="w-4 h-4 text-red-400" />
                      </div>
                      <div className="flex-1 min-w-0">
                        <p className="text-sm font-medium truncate text-white">{file.name}</p>
                        <p className="text-xs text-gray-400">{Math.round(file.size / 1024)} KB</p>
                      </div>
                    </div>
                  </div>
                )}
                
                <div className="flex flex-col space-y-4">
                  <Button 
                    className="w-full h-10 bg-gradient-to-r from-red-600 to-red-400 text-white rounded-lg hover:opacity-90 transition-opacity"
                    onClick={analyzeFile}
                    disabled={!file || analyzing || !moduleLoaded}
                  >
                    {analyzing ? (
                      <>
                        <div className="mr-2 h-4 w-4 rounded-full border-2 border-white border-t-transparent animate-spin" />
                        Analyzing...
                      </>
                    ) : "Analyze File"}
                  </Button>
                  
                  {/* Engine status */}
                  <div className="neo-blur rounded-lg p-4">
                    <div className="flex items-center justify-between text-xs">
                      <span className="text-gray-400">Module Status</span>
                      <div className="flex items-center gap-2">
                        <div className={`w-2 h-2 rounded-full ${moduleLoaded ? "bg-green-500" : "bg-yellow-500"}`}></div>
                        <span className="text-gray-300">{moduleLoaded ? "Ready" : "Loading..."}</span>
                      </div>
                    </div>
                    
                    {!moduleLoaded && (
                      <Progress value={loadingProgress} className="h-1 bg-gray-800 mt-2" />
                    )}
                  </div>
                </div>
              </div>
            </div>
          )}
          
          {/* Analysis Results - Only show after analysis */}
          {analysisData && (
            <div className="w-full">
              <div className="glass-morphism rounded-xl overflow-hidden transform transition-all hover:translate-y-[-2px] hover:shadow-[0_8px_20px_-2px_rgba(0,0,0,0.3)]">
                <div className="p-5 border-b border-white/5 flex flex-wrap md:flex-row md:items-center justify-between gap-4">
                  <div className="flex items-center gap-3">
                    <div className="p-2 rounded-lg bg-gradient-to-br from-red-500/20 to-red-700/10 border border-red-500/30">
                      <Database className="w-5 h-5 text-red-400" />
                    </div>
                    <div>
                      <h2 className="text-xl font-semibold text-white">Analysis Results</h2>
                      <p className="text-xs text-gray-400">{file?.name}</p>
                    </div>
                  </div>
                  
                  <div className="flex items-center gap-2">
                    {analysisData.signature.isSigned && (
                      <div className={`flex items-center gap-2 px-3 py-2 rounded-lg text-sm ${
                        analysisData.signature.isValid 
                          ? "bg-green-500/10 text-green-300 border border-green-500/20" 
                          : "bg-yellow-500/10 text-yellow-300 border border-yellow-500/20"
                      }`}>
                        {analysisData.signature.isValid 
                          ? <CheckCircle className="w-4 h-4" /> 
                          : <AlertTriangle className="w-4 h-4" />}
                        {analysisData.signature.isValid 
                          ? "Valid Signature" 
                          : "Invalid Signature"}
                      </div>
                    )}
                    
                    {/* Upload new file button */}
                    <Button 
                      variant="outline"
                      className="bg-white/5 border border-white/10 hover:bg-white/10 px-3 py-2 h-auto flex items-center gap-2"
                      onClick={() => setShowUpload(true)}
                    >
                      <Upload className="w-4 h-4" />
                      <span>New File</span>
                    </Button>
                  </div>
                </div>
                
                <Tabs defaultValue="header" className="w-full">
                  <div className="px-2 border-b border-white/5 overflow-x-auto scrollbar-none">
                    <TabsList className="bg-transparent h-auto p-0 flex w-max">
                      <TabsTrigger 
                        value="header" 
                        className="data-[state=active]:bg-red-500/10 data-[state=active]:text-red-400 data-[state=active]:border-red-500 data-[state=active]:shadow-none rounded-none border-b-2 border-transparent px-5 py-3 flex items-center gap-2"
                      >
                        <div className="w-1.5 h-1.5 rounded-full bg-red-400"></div>
                        Header
                      </TabsTrigger>
                      <TabsTrigger 
                        value="sections" 
                        className="data-[state=active]:bg-red-500/10 data-[state=active]:text-red-400 data-[state=active]:border-red-500 data-[state=active]:shadow-none rounded-none border-b-2 border-transparent px-5 py-3 flex items-center gap-2"
                      >
                        <div className="w-1.5 h-1.5 rounded-full bg-red-400"></div>
                        Sections
                      </TabsTrigger>
                      <TabsTrigger 
                        value="imports" 
                        className="data-[state=active]:bg-red-500/10 data-[state=active]:text-red-400 data-[state=active]:border-red-500 data-[state=active]:shadow-none rounded-none border-b-2 border-transparent px-5 py-3 flex items-center gap-2"
                      >
                        <div className="w-1.5 h-1.5 rounded-full bg-red-400"></div>
                        Imports
                      </TabsTrigger>
                      <TabsTrigger 
                        value="resources" 
                        className="data-[state=active]:bg-red-500/10 data-[state=active]:text-red-400 data-[state=active]:border-red-500 data-[state=active]:shadow-none rounded-none border-b-2 border-transparent px-5 py-3 flex items-center gap-2"
                      >
                        <div className="w-1.5 h-1.5 rounded-full bg-red-400"></div>
                        Resources
                      </TabsTrigger>
                      <TabsTrigger 
                        value="signature" 
                        className="data-[state=active]:bg-red-500/10 data-[state=active]:text-red-400 data-[state=active]:border-red-500 data-[state=active]:shadow-none rounded-none border-b-2 border-transparent px-5 py-3 flex items-center gap-2"
                      >
                        <div className="w-1.5 h-1.5 rounded-full bg-red-400"></div>
                        Signature
                      </TabsTrigger>
                    </TabsList>
                  </div>
                  
                  <TabsContent value="header" className="p-5 animate-fade-in">
                    <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
                      <div className="neo-blur rounded-xl p-4 transform transition-all hover:translate-y-[-2px] hover:bg-white/10">
                        <p className="text-xs text-gray-400 mb-1">Format</p>
                        <div className="flex items-baseline gap-2">
                          <p className="font-medium text-white text-xl">{analysisData.header.format}</p>
                        </div>
                      </div>
                      <div className="neo-blur rounded-xl p-4 transform transition-all hover:translate-y-[-2px] hover:bg-white/10">
                        <p className="text-xs text-gray-400 mb-1">Machine</p>
                        <div className="flex items-baseline gap-2">
                          <p className="font-medium text-white text-xl">{analysisData.header.machine.type}</p>
                        </div>
                        <p className="text-xs text-gray-500">{analysisData.header.machine.code}</p>
                      </div>
                      <div className="neo-blur rounded-xl p-4 transform transition-all hover:translate-y-[-2px] hover:bg-white/10">
                        <p className="text-xs text-gray-400 mb-1">Entry Point</p>
                        <div className="flex items-baseline gap-2">
                          <p className="font-medium text-white text-xl font-mono">{analysisData.header.entryPoint}</p>
                        </div>
                      </div>
                      <div className="neo-blur rounded-xl p-4 transform transition-all hover:translate-y-[-2px] hover:bg-white/10">
                        <p className="text-xs text-gray-400 mb-1">Section Count</p>
                        <div className="flex items-baseline gap-2">
                          <p className="font-medium text-white text-xl">{analysisData.header.sectionCount}</p>
                        </div>
                      </div>
                      
                      {/* DOS Header Information */}
                      <div className="neo-blur rounded-xl p-4 transform transition-all hover:translate-y-[-2px] hover:bg-white/10">
                        <p className="text-xs text-gray-400 mb-1">DOS Magic</p>
                        <div className="flex items-baseline gap-2">
                          <p className="font-medium text-white text-xl font-mono">{analysisData.header.dosHeader?.e_magic}</p>
                        </div>
                        <p className="text-xs text-gray-500">MZ Header</p>
                      </div>
                      <div className="neo-blur rounded-xl p-4 transform transition-all hover:translate-y-[-2px] hover:bg-white/10">
                        <p className="text-xs text-gray-400 mb-1">PE Offset</p>
                        <div className="flex items-baseline gap-2">
                          <p className="font-medium text-white text-xl font-mono">{analysisData.header.dosHeader?.e_lfanew}</p>
                        </div>
                      </div>
                      
                      {/* File Header Information */}
                      <div className="neo-blur rounded-xl p-4 transform transition-all hover:translate-y-[-2px] hover:bg-white/10">
                        <p className="text-xs text-gray-400 mb-1">Timestamp</p>
                        <div className="flex items-baseline gap-2">
                          <p className="font-medium text-white text-xl font-mono">
                            {new Date(analysisData.header.fileHeader?.timestamp * 1000).toLocaleDateString()}
                          </p>
                        </div>
                        <p className="text-xs text-gray-500">
                          {new Date(analysisData.header.fileHeader?.timestamp * 1000).toLocaleTimeString()}
                        </p>
                      </div>
                      <div className="neo-blur rounded-xl p-4 transform transition-all hover:translate-y-[-2px] hover:bg-white/10">
                        <p className="text-xs text-gray-400 mb-1">Characteristics</p>
                        <div className="flex items-baseline gap-2">
                          <p className="font-medium text-white text-xl font-mono">{analysisData.header.fileHeader?.characteristics?.value}</p>
                        </div>
                        <TooltipProvider>
                          <Tooltip>
                            <TooltipTrigger>
                              <p className="text-xs text-gray-500 underline cursor-help">View flags</p>
                            </TooltipTrigger>
                            <TooltipContent className="max-w-xs">
                              <ul className="text-xs space-y-1">
                                {analysisData.header.fileHeader?.characteristics?.flags?.map((flag: string, i: number) => (
                                  <li key={i}>{flag}</li>
                                ))}
                              </ul>
                            </TooltipContent>
                          </Tooltip>
                        </TooltipProvider>
                      </div>
                      
                      {/* Optional Header Information */}
                      <div className="neo-blur rounded-xl p-4 transform transition-all hover:translate-y-[-2px] hover:bg-white/10">
                        <p className="text-xs text-gray-400 mb-1">Image Base</p>
                        <div className="flex items-baseline gap-2">
                          <p className="font-medium text-white text-xl font-mono">{analysisData.header.optionalHeader?.imageBase}</p>
                        </div>
                      </div>
                      <div className="neo-blur rounded-xl p-4 transform transition-all hover:translate-y-[-2px] hover:bg-white/10">
                        <p className="text-xs text-gray-400 mb-1">Subsystem</p>
                        <div className="flex items-baseline gap-2">
                          <p className="font-medium text-white text-xl">{analysisData.header.optionalHeader?.subsystem?.name}</p>
                        </div>
                        <p className="text-xs text-gray-500">Type: {analysisData.header.optionalHeader?.subsystem?.value}</p>
                      </div>
                      <div className="neo-blur rounded-xl p-4 transform transition-all hover:translate-y-[-2px] hover:bg-white/10">
                        <p className="text-xs text-gray-400 mb-1">Section Alignment</p>
                        <div className="flex items-baseline gap-2">
                          <p className="font-medium text-white text-xl">{analysisData.header.optionalHeader?.sectionAlignment} bytes</p>
                        </div>
                      </div>
                      <div className="neo-blur rounded-xl p-4 transform transition-all hover:translate-y-[-2px] hover:bg-white/10">
                        <p className="text-xs text-gray-400 mb-1">File Alignment</p>
                        <div className="flex items-baseline gap-2">
                          <p className="font-medium text-white text-xl">{analysisData.header.optionalHeader?.fileAlignment} bytes</p>
                        </div>
                      </div>
                    </div>
                    
                    {/* Data Directories */}
                    <div className="mt-6">
                      <h3 className="text-sm font-medium text-white mb-3">Data Directories</h3>
                      <div className="overflow-x-auto">
                        <table className="w-full border-collapse min-w-[500px]">
                          <thead>
                            <tr className="text-left border-b border-white/10">
                              <th className="pb-3 px-4 text-xs font-medium text-gray-400">Name</th>
                              <th className="pb-3 px-4 text-xs font-medium text-gray-400">Virtual Address</th>
                              <th className="pb-3 px-4 text-xs font-medium text-gray-400">Size</th>
                            </tr>
                          </thead>
                          <tbody>
                            {analysisData.header.optionalHeader?.dataDirectories?.map((dir: any, index: number) => (
                              <tr key={index} className="border-b border-white/5 hover:bg-white/5 transition-colors">
                                <td className="py-2 px-4 text-white">{dir.name}</td>
                                <td className="py-2 px-4 font-mono text-white">{dir.virtualAddress}</td>
                                <td className="py-2 px-4 text-white">{dir.size} bytes</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  </TabsContent>
                  
                  <TabsContent value="sections" className="px-2 py-5 animate-fade-in">
                    <div className="overflow-x-auto">
                      <table className="w-full border-collapse min-w-[800px]">
                        <thead>
                          <tr className="text-left border-b border-white/10">
                            <th className="pb-3 px-4 text-xs font-medium text-gray-400">Name</th>
                            <th className="pb-3 px-4 text-xs font-medium text-gray-400">Virtual Address</th>
                            <th className="pb-3 px-4 text-xs font-medium text-gray-400">Virtual Size</th>
                            <th className="pb-3 px-4 text-xs font-medium text-gray-400">Raw Size</th>
                            <th className="pb-3 px-4 text-xs font-medium text-gray-400">Entropy</th>
                            <th className="pb-3 px-4 text-xs font-medium text-gray-400">Chi²</th>
                          </tr>
                        </thead>
                        <tbody>
                          {analysisData.sections.map((section: any, index: number) => (
                            <tr key={index} className="border-b border-white/5 hover:bg-white/5 transition-colors">
                              <td className="py-3 px-4">
                                <HoverCard>
                                  <HoverCardTrigger asChild>
                                    <div className="cursor-help">
                                      <div className="font-mono text-red-300">{section.name}</div>
                                      <div className="text-xs text-gray-400">{section.nameASCII}</div>
                                    </div>
                                  </HoverCardTrigger>
                                  <HoverCardContent className="neo-blur border border-red-500/20 w-64">
                                    <div className="flex justify-between">
                                      <div className="text-sm font-medium text-white">Section {index + 1}</div>
                                      <div className="text-xs text-gray-400">MD5 Hash:</div>
                                    </div>
                                    <div className="text-xs font-mono text-gray-300 truncate mt-1">
                                      {section.md5}
                                    </div>
                                  </HoverCardContent>
                                </HoverCard>
                              </td>
                              <td className="py-3 px-4">
                                <div className="font-mono text-white">{section.virtualAddress.hex}</div>
                                <div className="text-xs text-gray-400">{section.virtualAddress.decimal}</div>
                              </td>
                              <td className="py-3 px-4">
                                <div className="font-mono text-white">{section.virtualSize.hex}</div>
                                <div className="text-xs text-gray-400">{section.virtualSize.decimal}</div>
                              </td>
                              <td className="py-3 px-4">
                                <div className="font-mono text-white">{section.rawSize.hex}</div>
                                <div className="text-xs text-gray-400">{section.rawSize.decimal}</div>
                              </td>
                              <td className="py-3 px-4">
                                <div className={`${
                                  section.entropy > 7.0 ? "text-red-400" : 
                                  section.entropy > 6.5 ? "text-yellow-400" : 
                                  "text-green-400"
                                } font-medium`}>
                                  {section.entropy.toFixed(4)}
                                </div>
                              </td>
                              <td className="py-3 px-4">
                                <div className="text-white">{section.chiSquared.toFixed(2)}</div>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </TabsContent>
                  
                  <TabsContent value="imports" className="p-5 animate-fade-in">
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      {analysisData.imports.map((imp: any, index: number) => (
                        <div key={index} className="neo-blur rounded-xl border border-white/10 transform transition-all hover:translate-y-[-2px] hover:bg-white/10">
                          <div className="p-4 border-b border-white/10">
                            <div className="flex items-center justify-between">
                              <div className="flex items-center gap-2">
                                <div className="w-8 h-8 rounded-full bg-gradient-to-br from-red-500/20 to-red-700/10 flex items-center justify-center">
                                  <Code className="w-4 h-4 text-red-400" />
                                </div>
                                <h3 className="font-medium text-white">{imp.dll}</h3>
                              </div>
                              <span className="text-xs py-1 px-2 rounded-full bg-black/30 text-gray-300">
                                {imp.functionCount} functions
                              </span>
                            </div>
                          </div>
                          
                          <div className="p-4">
                            <div className="space-y-1">
                              {imp.functions.map((func: string, i: number) => (
                                <div 
                                  key={i} 
                                  className="text-sm py-1.5 px-2 rounded hover:bg-white/5 flex items-center gap-2 transition-colors"
                                >
                                  <span className="w-1.5 h-1.5 rounded-full bg-red-500/50"></span>
                                  <span className="font-mono text-xs text-gray-300">{func}</span>
                                </div>
                              ))}
                            </div>
                            
                            {imp.functions.length < imp.functionCount && (
                              <button className="mt-3 text-xs flex items-center gap-1 text-red-400 hover:text-red-300 transition-colors group">
                                <span>Show all functions</span>
                                <ChevronDown className="w-3 h-3 group-hover:translate-y-0.5 transition-transform" />
                              </button>
                            )}
                          </div>
                        </div>
                      ))}
                    </div>
                  </TabsContent>
                  
                  <TabsContent value="resources" className="p-5 animate-fade-in">
                    <div className="space-y-4">
                      {analysisData.resources.map((res: any, index: number) => (
                        <div key={index} className="neo-blur rounded-xl transform transition-all hover:translate-y-[-2px] hover:bg-white/10 border border-white/10 overflow-hidden">
                          <div className="p-4 border-b border-white/10">
                            <div className="flex items-center justify-between">
                              <div className="flex items-center gap-3">
                                <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-red-500/20 to-red-700/10 border border-red-500/30 flex items-center justify-center">
                                  <Database className="w-5 h-5 text-red-400" />
                                </div>
                                <div>
                                  <h3 className="font-medium text-white">{res.type}</h3>
                                  <div className="flex items-center gap-2 text-xs text-gray-400 mt-0.5">
                                    <span>{res.language}</span>
                                    <span className="w-1 h-1 rounded-full bg-gray-500"></span>
                                    <span>{res.size} bytes</span>
                                  </div>
                                </div>
                              </div>
                            </div>
                          </div>
                          
                          <div className="p-4">
                            <div className="grid grid-cols-2 gap-4 mb-4">
                              <div className="bg-black/30 rounded-lg p-3 text-center">
                                <div className="text-xs text-gray-400 mb-1">Entropy</div>
                                <div className={`text-sm font-medium ${
                                  res.entropy > 7.0 ? "text-red-400" : 
                                  res.entropy > 6.5 ? "text-yellow-400" : 
                                  "text-green-400"
                                }`}>
                                  {res.entropy.toFixed(3)}
                                </div>
                              </div>
                              <div className="bg-black/30 rounded-lg p-3 text-center">
                                <div className="text-xs text-gray-400 mb-1">Chi²</div>
                                <div className="text-sm font-medium text-white">
                                  {res.chiSquared.toFixed(2)}
                                </div>
                              </div>
                            </div>
                            
                            <div className="pt-3 border-t border-white/5">
                              <div className="flex items-center justify-between mb-1">
                                <div className="text-xs text-gray-400">SHA-256</div>
                                <button 
                                  className="text-xs text-red-400 hover:text-red-300 transition-colors flex items-center gap-1"
                                  onClick={() => {
                                    navigator.clipboard.writeText(res.sha256);
                                    toast({
                                      title: "Hash copied to clipboard",
                                      description: "SHA-256 hash has been copied to your clipboard",
                                    });
                                  }}
                                >
                                  <span>Copy</span>
                                  <ExternalLink className="w-3 h-3" />
                                </button>
                              </div>
                              <div className="font-mono text-xs text-gray-300 break-all bg-black/20 p-2 rounded">
                                {res.sha256}
                              </div>
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </TabsContent>
                  
                  <TabsContent value="signature" className="p-5 animate-fade-in">
                    <div className="neo-blur border border-white/10 rounded-xl p-6 flex flex-col items-center">
                      {analysisData.signature.isSigned ? (
                        <>
                          <div className={`w-20 h-20 rounded-full flex items-center justify-center ${
                            analysisData.signature.isValid 
                              ? "bg-gradient-to-br from-green-500/20 to-green-700/10 border border-green-500/30" 
                              : "bg-gradient-to-br from-yellow-500/20 to-yellow-700/10 border border-yellow-500/30"
                          } mb-6`}>
                            {analysisData.signature.isValid ? (
                              <CheckCircle className="w-10 h-10 text-green-400" />
                            ) : (
                              <AlertTriangle className="w-10 h-10 text-yellow-400" />
                            )}
                          </div>
                          <h3 className="text-xl font-medium text-white mb-2">
                            {analysisData.signature.isValid ? "Valid Digital Signature" : "Invalid Signature"}
                          </h3>
                          <p className="text-gray-400 text-center max-w-md mb-4">
                            {analysisData.signature.isValid 
                              ? "This executable is digitally signed and the signature is valid." 
                              : "This executable is signed but the signature validation failed."}
                          </p>
                          {analysisData.signature.signer && (
                            <div className="neo-blur p-4 rounded-lg w-full max-w-md">
                              <div className="flex items-center justify-between mb-2">
                                <span className="text-sm text-gray-400">Signed By</span>
                                <span className="text-sm font-medium text-white">{analysisData.signature.signer}</span>
                              </div>
                            </div>
                          )}
                        </>
                      ) : (
                        <>
                          <div className="w-20 h-20 rounded-full bg-gradient-to-br from-gray-500/20 to-gray-700/10 border border-gray-500/30 flex items-center justify-center mb-6">
                            <Lock className="w-10 h-10 text-gray-400" />
                          </div>
                          <h3 className="text-xl font-medium text-white mb-2">Unsigned Executable</h3>
                          <p className="text-gray-400 text-center max-w-md">
                            This executable does not contain a digital signature.
                          </p>
                        </>
                      )}
                    </div>
                  </TabsContent>
                </Tabs>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default Index;
