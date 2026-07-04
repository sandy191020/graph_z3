import base64
import os
import tempfile
import dash
from dash import dcc, html, Input, Output, State, ctx
import dash_cytoscape as cyto
import networkx as nx
from dataclasses import asdict

from src.core.binary_loader import BinaryLoader
from src.graph.graph_builder import GraphBuilder
from src.core.interfaces import AnalysisBackendProvider, ExecutionState

try:
    cyto.load_extra_layouts()
except Exception:
    pass

def nx_to_cyto(G):
    elements = []
    for node, data in G.nodes(data=True):
        classes = data.get('node_class', 'internal')
        elements.append({
            'data': {'id': str(node), 'label': data.get('label', str(node)), **data},
            'classes': classes
        })
    for src, dst in G.edges():
        elements.append({
            'data': {'source': str(src), 'target': str(dst)}
        })
    return elements

def create_app():
    app = dash.Dash(__name__, external_stylesheets=[
        'https://stackpath.bootstrapcdn.com/bootswatch/4.5.2/darkly/bootstrap.min.css'
    ])

    stylesheet = [
        {
            'selector': 'node',
            'style': {
                'content': 'data(label)',
                'text-valign': 'center',
                'text-halign': 'center',
                'shape': 'round-rectangle',
                'width': 'label',
                'height': 'label',
                'padding': '10px',
                'color': '#ffffff',
                'font-family': 'monospace',
                'font-size': '12px',
                'text-wrap': 'wrap',
                'text-max-width': '150px'
            }
        },
        {'selector': '.internal', 'style': {'background-color': '#2980b9'}},
        {'selector': '.entry', 'style': {'background-color': '#27ae60'}},
        {'selector': '.library', 'style': {'background-color': '#8e44ad'}},
        {
            'selector': 'node:selected',
            'style': {
                'background-color': '#f1c40f',
                'border-width': '2px',
                'border-color': '#f39c12',
                'color': '#000000'
            }
        },
        {
            'selector': '.active-execution-node',
            'style': {
                'background-color': '#e74c3c',
                'border-width': '4px',
                'border-color': '#c0392b',
                'color': '#ffffff'
            }
        },
        {
            'selector': 'edge',
            'style': {
                'curve-style': 'bezier',
                'target-arrow-shape': 'triangle',
                'line-color': '#7f8c8d',
                'target-arrow-color': '#7f8c8d',
                'width': 2,
                'opacity': 0.6
            }
        }
    ]

    app.layout = html.Div(style={'display': 'flex', 'height': '100vh', 'fontFamily': 'sans-serif'}, children=[
        
        # LEFT PANEL: Controls & Details
        html.Div(style={'width': '350px', 'padding': '20px', 'backgroundColor': '#1e2227', 'color': '#abb2bf', 'overflowY': 'auto', 'borderRight': '1px solid #2c313a'}, children=[
            html.H3("Ghidra-UI Mode", style={'color': '#61afef', 'fontWeight': 'bold'}),
            html.Hr(style={'borderColor': '#2c313a'}),
            
            html.H5("1. Binary Upload", style={'color': '#e5c07b'}),
            dcc.Upload(
                id='upload-binary',
                children=html.Div(['Drag & Drop Binary Here']),
                style={
                    'width': '100%', 'height': '50px', 'lineHeight': '50px',
                    'borderWidth': '1px', 'borderStyle': 'dashed', 'borderColor': '#5c6370',
                    'borderRadius': '5px', 'textAlign': 'center', 'marginBottom': '10px',
                    'cursor': 'pointer', 'backgroundColor': '#282c34'
                },
                multiple=False
            ),
            dcc.Loading(type="circle", children=html.Div(id='upload-status', style={'color': '#98c379', 'marginBottom': '15px'})),
            
            html.H5("2. Graph Settings", style={'color': '#e5c07b'}),
            dcc.Dropdown(
                id='graph-selector',
                options=[{'label': 'Control Flow Graph (CFG)', 'value': 'cfg'}, {'label': 'Call Graph (CG)', 'value': 'cg'}],
                value='cfg', clearable=False, style={'color': 'black', 'marginBottom': '10px'}
            ),
            
            html.H5("3. Dashboard Stats", style={'color': '#e5c07b'}),
            html.Div(id='dashboard-stats', children="No binary loaded.", style={
                'backgroundColor': '#282c34', 'padding': '15px', 'borderRadius': '5px', 'fontSize': '13px', 'marginBottom': '20px', 'border': '1px solid #2c313a'
            }),

            html.H5("4. Node Inspector", style={'color': '#e5c07b'}),
            html.Div(id='node-details', children="Select a node to inspect.", style={
                'whiteSpace': 'pre-wrap', 'wordBreak': 'break-all', 'backgroundColor': '#282c34', 
                'padding': '15px', 'borderRadius': '5px', 'fontSize': '13px', 'border': '1px solid #2c313a'
            })
        ]),
        
        # CENTER PANEL: Cytoscape Graph
        html.Div(style={'flex': 1, 'position': 'relative', 'backgroundColor': '#282c34'}, children=[
            cyto.Cytoscape(
                id='cytoscape-graph',
                layout={'name': 'breadthfirst', 'directed': True, 'spacingFactor': 1.5},
                style={'width': '100%', 'height': '100%'},
                elements=[],
                stylesheet=stylesheet,
                minZoom=0.1,
                maxZoom=3.0,
                boxSelectionEnabled=True
            )
        ]),
        
        # RIGHT PANEL: Execution State & SMT Constraint Viewer
        html.Div(style={'width': '400px', 'padding': '20px', 'backgroundColor': '#1e2227', 'color': '#abb2bf', 'overflowY': 'auto', 'borderLeft': '1px solid #2c313a'}, children=[
            html.H4("Execution Trace", style={'color': '#98c379', 'fontWeight': 'bold'}),
            html.Hr(style={'borderColor': '#2c313a'}),
            
            html.Div([
                html.Button('⏮', id='btn-reset', n_clicks=0, className='btn btn-secondary btn-sm', style={'marginRight': '5px'}),
                html.Button('◀', id='btn-prev', n_clicks=0, className='btn btn-info btn-sm', style={'marginRight': '5px'}),
                html.Button('▶', id='btn-next', n_clicks=0, className='btn btn-info btn-sm', style={'marginRight': '5px'}),
                html.Button('⏯ Play/Pause', id='btn-play', n_clicks=0, className='btn btn-success btn-sm')
            ], style={'marginBottom': '20px', 'textAlign': 'center'}),
            
            html.Div(id='state-viewer', children="No trace loaded.", style={
                'whiteSpace': 'pre-wrap', 'wordBreak': 'break-all', 'backgroundColor': '#282c34', 
                'padding': '15px', 'borderRadius': '5px', 'fontSize': '13px', 'border': '1px solid #2c313a',
                'marginBottom': '20px'
            }),
            
            html.H5("SMT Constraint Diagnostics", style={'color': '#c678dd', 'fontWeight': 'bold'}),
            html.Div(id='smt-viewer', children="Awaiting solver input...", style={
                'backgroundColor': '#282c34', 
                'padding': '15px', 'borderRadius': '5px', 'fontSize': '13px', 'border': '1px solid #c678dd'
            }),
            
            dcc.Interval(id='play-interval', interval=800, n_intervals=0, disabled=True),
            
            dcc.Store(id='cfg-store'),
            dcc.Store(id='cg-store'),
            dcc.Store(id='trace-store', data=[]),
            dcc.Store(id='trace-index', data=0),
            dcc.Store(id='play-state', data=False)
        ])
    ])

    @app.callback(
        Output('upload-status', 'children'),
        Output('cfg-store', 'data'),
        Output('cg-store', 'data'),
        Output('trace-store', 'data'),
        Output('dashboard-stats', 'children'),
        Input('upload-binary', 'contents'),
        State('upload-binary', 'filename')
    )
    def handle_upload(contents, filename):
        if contents is None:
            return dash.no_update, dash.no_update, dash.no_update, dash.no_update, dash.no_update
            
        try:
            content_type, content_string = contents.split(',')
            decoded = base64.b64decode(content_string)
            
            fd, temp_path = tempfile.mkstemp(prefix="angr_target_")
            with open(temp_path, "wb") as f:
                f.write(decoded)
            os.close(fd)
            
            loader = BinaryLoader(temp_path)
            loader.analyze()
            
            builder = GraphBuilder(loader)
            nx_cfg = builder.build_networkx_cfg()
            nx_cg = builder.build_networkx_cg()
            
            cfg_elements = nx_to_cyto(nx_cfg)
            cg_elements = nx_to_cyto(nx_cg)
            
            # Fetch abstract execution trace from the connected backend provider
            backend_provider = AnalysisBackendProvider(temp_path)
            raw_trace = backend_provider.get_execution_trace()
            
            # Convert dataclass objects to dicts for dcc.Store serialization
            trace = []
            for state_obj in raw_trace:
                state_dict = asdict(state_obj)
                
                # Fetch accompanying SMT solver diagnostics for this state
                smt_result = backend_provider.get_constraint_result(state_obj)
                state_dict['smt_diagnostics'] = asdict(smt_result)
                
                trace.append(state_dict)
            
            os.remove(temp_path)
            
            lib_funcs = sum(1 for _, data in nx_cg.nodes(data=True) if data.get('is_library_call', False))
            
            stats = [
                html.Strong("Total Functions: "), str(nx_cg.number_of_nodes()), html.Br(),
                html.Strong("Library Functions: "), str(lib_funcs), html.Br(),
                html.Strong("Call Graph Edges: "), str(nx_cg.number_of_edges()), html.Br(),
                html.Strong("Total Basic Blocks (CFG): "), str(nx_cfg.number_of_nodes()), html.Br(),
                html.Strong("CFG Edges: "), str(nx_cfg.number_of_edges())
            ]
            
            return f"✅ {filename} Analyzed", cfg_elements, cg_elements, trace, stats
            
        except Exception as e:
            return f"❌ Error: {str(e)}", [], [], [], f"Analysis failed: {str(e)}"

    @app.callback(
        Output('trace-index', 'data'),
        Output('play-state', 'data'),
        Output('play-interval', 'disabled'),
        Input('btn-next', 'n_clicks'),
        Input('btn-prev', 'n_clicks'),
        Input('btn-reset', 'n_clicks'),
        Input('btn-play', 'n_clicks'),
        Input('play-interval', 'n_intervals'),
        State('trace-index', 'data'),
        State('trace-store', 'data'),
        State('play-state', 'data')
    )
    def update_trace_index(btn_n, btn_p, btn_r, btn_play, n_intervals, current_idx, trace, is_playing):
        if not trace:
            return 0, False, True
            
        triggered = ctx.triggered_id
        
        if triggered == 'btn-reset':
            return 0, False, True
        elif triggered == 'btn-next':
            return min(current_idx + 1, len(trace) - 1), False, True
        elif triggered == 'btn-prev':
            return max(current_idx - 1, 0), False, True
        elif triggered == 'btn-play':
            new_play_state = not is_playing
            if new_play_state and current_idx >= len(trace) - 1:
                return 0, new_play_state, not new_play_state
            return current_idx, new_play_state, not new_play_state
        elif triggered == 'play-interval':
            if current_idx >= len(trace) - 1:
                return current_idx, False, True
            return current_idx + 1, is_playing, False
            
        return current_idx, is_playing, not is_playing

    @app.callback(
        Output('cytoscape-graph', 'elements'),
        Output('state-viewer', 'children'),
        Output('smt-viewer', 'children'),
        Input('trace-index', 'data'),
        Input('graph-selector', 'value'),
        Input('cfg-store', 'data'),
        Input('cg-store', 'data'),
        State('trace-store', 'data')
    )
    def update_graph_and_viewer(trace_idx, selected_graph, cfg_data, cg_data, trace_data):
        elements = cfg_data if selected_graph == 'cfg' else cg_data
        if not elements:
            return [], "Upload a binary to begin.", "Waiting for analysis backend."
            
        viewer_content = "Waiting for analysis backend."
        smt_content = "Waiting for analysis backend."
        
        if trace_data and trace_idx < len(trace_data):
            state = trace_data[trace_idx]
            active_node_id = str(state.get('instruction_address'))
            
            for elem in elements:
                if 'id' in elem['data']:
                    if elem['data']['id'] == active_node_id:
                        elem['classes'] = elem.get('classes', '') + ' active-execution-node'
                    else:
                        elem['classes'] = elem.get('classes', '').replace(' active-execution-node', '')
            
            viewer_content = [
                html.H6(f"Execution Depth: {state.get('execution_depth')}", style={'color': '#e5c07b'}),
                html.Strong("Address: "), str(state.get('instruction_address')), html.Br(),
                html.Strong("Function: "), str(state.get('function_name')), html.Br(),
                html.Strong("Basic Block: "), str(state.get('basic_block')), html.Br(),
                html.Strong("Status: "), str(state.get('explanation')), html.Br(),
                html.Strong("Next State: "), str(state.get('next_state'))
            ]
            
            smt = state.get('smt_diagnostics', {})
            
            smt_content = [
                html.Strong("Constraint List:"), html.Br(), 
                html.Div(smt.get('constraint_list', 'Waiting for analysis backend.'), style={'fontFamily': 'monospace', 'color': '#98c379', 'backgroundColor': '#1e2227', 'padding': '5px', 'marginTop': '5px', 'marginBottom': '10px'}),
                
                html.Strong("Solver Status: "), html.Span(smt.get('status', 'N/A'), style={'color': '#e5c07b'}), html.Br(),
                
                html.Strong("Model Information:"), html.Br(),
                html.Div(smt.get('model', 'Waiting for analysis backend.'), style={'fontFamily': 'monospace', 'color': '#61afef', 'backgroundColor': '#1e2227', 'padding': '5px', 'marginTop': '5px', 'marginBottom': '10px'}),
                
                html.Strong("Solver Statistics:"), html.Br(),
                html.Div(smt.get('statistics', 'Waiting for analysis backend.'), style={'fontSize': '12px', 'color': '#abb2bf', 'marginBottom': '10px'}),
                
                html.Strong("Plain-English Explanation:"), html.Br(),
                html.Div(smt.get('explanation', 'Waiting for analysis backend.'), style={'fontStyle': 'italic', 'color': '#abb2bf', 'marginTop': '5px'})
            ]
            
        return elements, viewer_content, smt_content

    return app
