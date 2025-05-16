from flask_restx import Api, Namespace, Resource

api = None  # Будет инициализировано позже

def init_api(app):
    global api
    api = Api(app, version='1.0', title='My API', doc='/docs')
    
    auth_ns = Namespace('auth', description='Auth operations')
    
    @auth_ns.route('/test')
    class TestResource(Resource):
        def get(self):
            return {'message': 'API работает!'}
    
    api.add_namespace(auth_ns)