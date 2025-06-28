# path: /src/themes/theme.py
import os


def get_themes(window):
    """ 动态加载 /resources/themes 下的 .qss 文件，并添加到 theme_combo 下拉框中 """

    # 定义资源目录路径

    theme_dir = os.path.join(os.path.dirname(__file__), '..', '..', 'resource', 'themes')  # 使用正确的相对路径
   
    # 获取所有 .qss 文件
    qss_files = [f for f in os.listdir(theme_dir) if f.endswith(".qss")]

    # 清空下拉框并添加主题
    window.theme_combo.clear()

    # 将文件名添加到 theme_combo 下拉框
    for qss_file in qss_files:
        theme_name = qss_file.split('.')[0]  # 使用文件名（不包括扩展名）作为主题名
        window.theme_combo.addItem(theme_name, userData=qss_file)  # 使用 userData 储存文件名

    # 连接下拉框的改变事件，选择后更新主题
    window.theme_combo.currentTextChanged.connect(lambda: apply_theme(window))


# 当用户切换 theme 的时候,则更换 qss 样式
def apply_theme(window):
    """ 应用选中的主题 """
    selected_theme = window.theme_combo.currentData()  # 获取选中的 .qss 文件名
    if selected_theme:
        # 获取 qss 的路径
        theme_file_path = os.path.join(os.path.dirname(__file__), '..', '..', 'resource', 'themes',
                                       selected_theme)
        try:
            with open(theme_file_path, 'r', encoding='utf-8') as f:
                qss = f.read()
                window.setStyleSheet(qss)
        except Exception as e:
            pass


# 初始化主题为 dark
def init_themes(window):
    """ 初始化并加载主题列表 """

    # 默认选择第一个主题，假设已经有至少一个主题
    if window.theme_combo.count() > 0:
        window.theme_combo.setCurrentIndex(0)
        apply_theme(window)
